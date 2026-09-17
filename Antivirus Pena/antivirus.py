import os
import json
import shutil
import hashlib
import datetime
import threading
import queue
import tkinter as tk

from tkinter import ttk, filedialog, messagebox


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

APP_NAME = "Pena Antivirus"
VERSION = "1.0.0"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

RULES_DIR = os.path.join(BASE_DIR, "rules")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
LOG_DIR = os.path.join(BASE_DIR, "logs")

SIGNATURE_FILE = os.path.join(
    BASE_DIR,
    "signatures.json"
)

LOG_FILE = os.path.join(
    LOG_DIR,
    "scan_log.txt"
)

QUARANTINE_INDEX = os.path.join(
    QUARANTINE_DIR,
    "index.json"
)


# ============================================================
# OPTIONAL YARA IMPORT
# ============================================================

try:
    import yara

    YARA_AVAILABLE = True

except ImportError:
    yara = None
    YARA_AVAILABLE = False


# ============================================================
# CREATE REQUIRED DIRECTORIES
# ============================================================

for directory in (
    RULES_DIR,
    QUARANTINE_DIR,
    LOG_DIR
):
    os.makedirs(
        directory,
        exist_ok=True
    )


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def current_time():
    """
    Returns current local time in ISO format.
    """

    return datetime.datetime.now().astimezone().isoformat(
        timespec="seconds"
    )


def write_log(
    event,
    file_path="",
    details=""
):
    """
    Write scanner activity into log file.
    """

    try:

        with open(
            LOG_FILE,
            "a",
            encoding="utf-8"
        ) as log:

            log.write(
                f"[{current_time()}] "
                f"{event} | "
                f"{file_path} | "
                f"{details}\n"
            )

    except OSError:
        pass


def load_json(
    file_path,
    default
):
    """
    Load JSON file safely.
    """

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (
        OSError,
        json.JSONDecodeError
    ):

        return default


def save_json(
    file_path,
    data
):
    """
    Save JSON atomically.
    """

    temporary_file = file_path + ".tmp"

    with open(
        temporary_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False
        )

    os.replace(
        temporary_file,
        file_path
    )


# ============================================================
# HASH SIGNATURE DATABASE
# ============================================================

def load_signatures():

    data = load_json(
        SIGNATURE_FILE,
        {}
    )

    if isinstance(data, dict):
        return data

    return {}


SIGNATURES = load_signatures()


def find_hash_detection(
    sha256
):
    """
    Check SHA-256 against local signature database.
    """

    target = sha256.lower()

    for stored_hash, detection_name in SIGNATURES.items():

        if str(stored_hash).lower() == target:

            return str(detection_name)

    return None


# ============================================================
# YARA
# ============================================================

def load_yara_rules():

    if not YARA_AVAILABLE:

        return (
            None,
            "yara-python is not installed."
        )

    if not os.path.isdir(RULES_DIR):

        return (
            None,
            "Rules directory does not exist."
        )

    rule_files = {}

    for filename in os.listdir(RULES_DIR):

        if filename.lower().endswith(
            (
                ".yar",
                ".yara"
            )
        ):

            full_path = os.path.join(
                RULES_DIR,
                filename
            )

            namespace = os.path.splitext(
                filename
            )[0]

            rule_files[
                namespace
            ] = full_path

    if not rule_files:

        return (
            None,
            "No YARA rule files found."
        )

    try:

        compiled_rules = yara.compile(
            filepaths=rule_files
        )

        return (
            compiled_rules,
            None
        )

    except yara.Error as error:

        return (
            None,
            f"YARA compile error: {error}"
        )


YARA_RULES, YARA_ERROR = load_yara_rules()


# ============================================================
# SHA-256 CALCULATION
# ============================================================

def calculate_sha256(
    file_path,
    stop_event=None
):
    """
    Calculate SHA-256 using chunks.

    This avoids loading large files completely
    into memory.
    """

    sha256 = hashlib.sha256()

    try:

        with open(
            file_path,
            "rb"
        ) as file:

            while True:

                if (
                    stop_event
                    and stop_event.is_set()
                ):

                    return None

                chunk = file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                sha256.update(
                    chunk
                )

        return sha256.hexdigest()

    except (
        OSError,
        PermissionError
    ):

        return None


# ============================================================
# PATH UTILITIES
# ============================================================

def is_inside(
    file_path,
    directory
):
    """
    Check whether a path exists inside
    a particular directory.
    """

    try:

        file_path = os.path.abspath(
            file_path
        )

        directory = os.path.abspath(
            directory
        )

        return os.path.commonpath(
            [
                file_path,
                directory
            ]
        ) == directory

    except ValueError:

        return False


# ============================================================
# SINGLE FILE SCANNER
# ============================================================

def scan_file(
    file_path,
    stop_event=None
):

    result = {

        "path": file_path,

        "status": "CLEAN",

        "detection": "",

        "sha256": ""
    }


    # --------------------------------------------------------
    # CHECK STOP
    # --------------------------------------------------------

    if (
        stop_event
        and stop_event.is_set()
    ):

        result["status"] = "CANCELLED"

        return result


    # --------------------------------------------------------
    # SHA-256
    # --------------------------------------------------------

    file_hash = calculate_sha256(
        file_path,
        stop_event
    )


    if file_hash is None:

        result["status"] = "ERROR"

        result["detection"] = (
            "Unable to read file"
        )

        write_log(
            "SCAN_ERROR",
            file_path,
            result["detection"]
        )

        return result


    result["sha256"] = file_hash


    # --------------------------------------------------------
    # HASH SIGNATURE CHECK
    # --------------------------------------------------------

    detection = find_hash_detection(
        file_hash
    )


    if detection:

        result["status"] = "THREAT"

        result["detection"] = (
            f"HASH:{detection}"
        )

        write_log(
            "THREAT_DETECTED",
            file_path,
            result["detection"]
        )

        return result


    # --------------------------------------------------------
    # YARA CHECK
    # --------------------------------------------------------

    if YARA_RULES is not None:

        try:

            matches = YARA_RULES.match(
                file_path,
                timeout=30
            )

            if matches:

                rule_names = ",".join(
                    match.rule
                    for match in matches
                )

                result["status"] = "THREAT"

                result["detection"] = (
                    f"YARA:{rule_names}"
                )

                write_log(
                    "THREAT_DETECTED",
                    file_path,
                    result["detection"]
                )

                return result


        except Exception as error:

            result["status"] = "ERROR"

            result["detection"] = (
                f"YARA error: {error}"
            )

            write_log(
                "YARA_ERROR",
                file_path,
                result["detection"]
            )

            return result


    # --------------------------------------------------------
    # CLEAN
    # --------------------------------------------------------

    write_log(
        "CLEAN",
        file_path,
        file_hash
    )

    return result


# ============================================================
# DIRECTORY WALKER
# ============================================================

def iterate_files(
    folder,
    stop_event=None
):

    for root, directories, files in os.walk(
        folder
    ):

        if (
            stop_event
            and stop_event.is_set()
        ):

            return


        # ----------------------------------------------------
        # Ignore quarantine directory
        # ----------------------------------------------------

        filtered_directories = []

        for directory in directories:

            full_directory = os.path.join(
                root,
                directory
            )

            if not is_inside(
                full_directory,
                QUARANTINE_DIR
            ):

                filtered_directories.append(
                    directory
                )

        directories[:] = filtered_directories


        # ----------------------------------------------------
        # Files
        # ----------------------------------------------------

        for filename in files:

            file_path = os.path.join(
                root,
                filename
            )

            if is_inside(
                file_path,
                QUARANTINE_DIR
            ):

                continue

            yield file_path


# ============================================================
# DIRECTORY SCANNER
# ============================================================

def scan_directory(
    folder,
    result_callback,
    status_callback,
    stop_event
):

    total_files = 0

    threats = 0

    errors = 0


    for file_path in iterate_files(
        folder,
        stop_event
    ):

        if stop_event.is_set():
            break


        status_callback(
            f"Scanning: {file_path}"
        )


        result = scan_file(
            file_path,
            stop_event
        )


        total_files += 1


        if result["status"] == "THREAT":

            threats += 1


        elif result["status"] == "ERROR":

            errors += 1


        result_callback(
            result,
            total_files,
            threats,
            errors
        )


    return (
        total_files,
        threats,
        errors
    )


# ============================================================
# QUARANTINE
# ============================================================

def quarantine_file(
    original_path,
    detection
):

    if not os.path.isfile(
        original_path
    ):

        return (
            False,
            "File no longer exists."
        )


    # --------------------------------------------------------
    # Calculate hash
    # --------------------------------------------------------

    file_hash = calculate_sha256(
        original_path
    )


    if not file_hash:

        return (
            False,
            "Unable to calculate SHA-256."
        )


    # --------------------------------------------------------
    # Generate unique quarantine name
    # --------------------------------------------------------

    timestamp = datetime.datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )


    original_name = os.path.basename(
        original_path
    )


    safe_name = original_name.replace(
        "\x00",
        ""
    )


    quarantine_name = (
        f"{timestamp}_"
        f"{safe_name}"
        f".quarantined"
    )


    quarantine_path = os.path.join(
        QUARANTINE_DIR,
        quarantine_name
    )


    # --------------------------------------------------------
    # Load quarantine database
    # --------------------------------------------------------

    index = load_json(
        QUARANTINE_INDEX,
        {}
    )


    if not isinstance(
        index,
        dict
    ):

        index = {}


    # --------------------------------------------------------
    # Move file
    # --------------------------------------------------------

    try:

        shutil.move(
            original_path,
            quarantine_path
        )


        record_id = os.path.basename(
            quarantine_path
        )


        index[record_id] = {

            "original_path":
                original_path,

            "quarantine_path":
                quarantine_path,

            "sha256":
                file_hash,

            "detection":
                detection,

            "quarantined_at":
                current_time()
        }


        save_json(
            QUARANTINE_INDEX,
            index
        )


        write_log(
            "QUARANTINE",
            original_path,
            detection
        )


        return (
            True,
            quarantine_path
        )


    except (
        OSError,
        shutil.Error
    ) as error:

        write_log(
            "QUARANTINE_FAILED",
            original_path,
            str(error)
        )


        return (
            False,
            str(error)
        )


# ============================================================
# RESTORE QUARANTINED FILE
# ============================================================

def restore_file(
    record_id
):

    index = load_json(
        QUARANTINE_INDEX,
        {}
    )


    if record_id not in index:

        return (
            False,
            "Quarantine record not found."
        )


    record = index[
        record_id
    ]


    source = record[
        "quarantine_path"
    ]


    original = record[
        "original_path"
    ]


    # --------------------------------------------------------
    # Check source
    # --------------------------------------------------------

    if not os.path.isfile(
        source
    ):

        return (
            False,
            "Quarantined file is missing."
        )


    # --------------------------------------------------------
    # Don't overwrite existing file
    # --------------------------------------------------------

    if os.path.exists(
        original
    ):

        return (
            False,
            "Original location already contains a file."
        )


    try:

        os.makedirs(
            os.path.dirname(
                original
            ),
            exist_ok=True
        )


        shutil.move(
            source,
            original
        )


        del index[
            record_id
        ]


        save_json(
            QUARANTINE_INDEX,
            index
        )


        write_log(
            "RESTORE",
            original,
            record["detection"]
        )


        return (
            True,
            original
        )


    except (
        OSError,
        shutil.Error
    ) as error:

        return (
            False,
            str(error)
        )


# ============================================================
# MAIN APPLICATION
# ============================================================

class AntivirusApp(
    tk.Tk
):

    def __init__(self):

        super().__init__()


        # ----------------------------------------------------
        # Window
        # ----------------------------------------------------

        self.title(
            f"{APP_NAME} v{VERSION}"
        )


        self.geometry(
            "1150x700"
        )


        self.minsize(
            900,
            600
        )


        # ----------------------------------------------------
        # Scanner state
        # ----------------------------------------------------

        self.events = queue.Queue()

        self.stop_event = (
            threading.Event()
        )

        self.results = []

        self.current_folder = ""


        # ----------------------------------------------------
        # Build interface
        # ----------------------------------------------------

        self.build_interface()


        # ----------------------------------------------------
        # Event processor
        # ----------------------------------------------------

        self.after(
            100,
            self.process_events
        )


    # ========================================================
    # BUILD GUI
    # ========================================================

    def build_interface(
        self
    ):

        # ----------------------------------------------------
        # Header
        # ----------------------------------------------------

        header = ttk.Frame(
            self,
            padding=20
        )

        header.pack(
            fill="x"
        )


        ttk.Label(
            header,
            text=f"{APP_NAME} v{VERSION}",
            font=(
                "Segoe UI",
                24,
                "bold"
            )
        ).pack(
            anchor="w"
        )


        ttk.Label(
            header,
            text=(
                "Educational Endpoint Scanner | "
                "SHA-256 | YARA | Quarantine | Logs"
            )
        ).pack(
            anchor="w",
            pady=(5, 0)
        )


        # ----------------------------------------------------
        # Buttons
        # ----------------------------------------------------

        button_frame = ttk.Frame(
            self,
            padding=(
                20,
                0,
                20,
                10
            )
        )

        button_frame.pack(
            fill="x"
        )


        self.scan_button = ttk.Button(
            button_frame,
            text="Scan Folder",
            command=self.select_folder
        )

        self.scan_button.pack(
            side="left",
            padx=(0, 8)
        )


        self.stop_button = ttk.Button(
            button_frame,
            text="Stop Scan",
            command=self.stop_scan,
            state="disabled"
        )

        self.stop_button.pack(
            side="left",
            padx=(0, 8)
        )


        self.quarantine_button = ttk.Button(
            button_frame,
            text="Quarantine Selected",
            command=self.quarantine_selected
        )

        self.quarantine_button.pack(
            side="left",
            padx=(0, 8)
        )


        self.restore_button = ttk.Button(
            button_frame,
            text="Restore",
            command=self.show_restore_window
        )

        self.restore_button.pack(
            side="left",
            padx=(0, 8)
        )


        self.clear_button = ttk.Button(
            button_frame,
            text="Clear",
            command=self.clear_results
        )

        self.clear_button.pack(
            side="left"
        )


        # ----------------------------------------------------
        # Progress bar
        # ----------------------------------------------------

        self.progress = ttk.Progressbar(
            self,
            mode="indeterminate"
        )

        self.progress.pack(
            fill="x",
            padx=20
        )


        # ----------------------------------------------------
        # Status
        # ----------------------------------------------------

        self.status_variable = tk.StringVar(
            value="Ready."
        )


        ttk.Label(
            self,
            textvariable=self.status_variable,
            padding=(
                20,
                8
            )
        ).pack(
            fill="x"
        )


        # ----------------------------------------------------
        # Table
        # ----------------------------------------------------

        table_frame = ttk.Frame(
            self,
            padding=20
        )

        table_frame.pack(
            fill="both",
            expand=True
        )


        columns = (
            "status",
            "file",
            "detection",
            "sha256"
        )


        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="extended"
        )


        # ----------------------------------------------------
        # Headings
        # ----------------------------------------------------

        self.tree.heading(
            "status",
            text="Status"
        )

        self.tree.heading(
            "file",
            text="File"
        )

        self.tree.heading(
            "detection",
            text="Detection"
        )

        self.tree.heading(
            "sha256",
            text="SHA-256"
        )


        # ----------------------------------------------------
        # Column sizes
        # ----------------------------------------------------

        self.tree.column(
            "status",
            width=100,
            anchor="center"
        )

        self.tree.column(
            "file",
            width=430,
            anchor="w"
        )

        self.tree.column(
            "detection",
            width=220,
            anchor="w"
        )

        self.tree.column(
            "sha256",
            width=350,
            anchor="w"
        )


        # ----------------------------------------------------
        # Scrollbars
        # ----------------------------------------------------

        vertical_scroll = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.tree.yview
        )


        horizontal_scroll = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=self.tree.xview
        )


        self.tree.configure(
            yscrollcommand=vertical_scroll.set,
            xscrollcommand=horizontal_scroll.set
        )


        self.tree.grid(
            row=0,
            column=0,
            sticky="nsew"
        )


        vertical_scroll.grid(
            row=0,
            column=1,
            sticky="ns"
        )


        horizontal_scroll.grid(
            row=1,
            column=0,
            sticky="ew"
        )


        table_frame.rowconfigure(
            0,
            weight=1
        )


        table_frame.columnconfigure(
            0,
            weight=1
        )


        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        self.summary_variable = tk.StringVar(
            value=(
                "Files: 0 | "
                "Threats: 0 | "
                "Errors: 0"
            )
        )


        ttk.Label(
            self,
            textvariable=self.summary_variable,
            padding=(
                20,
                10
            )
        ).pack(
            fill="x"
        )


        # ----------------------------------------------------
        # YARA status
        # ----------------------------------------------------

        if not YARA_AVAILABLE:

            self.status_variable.set(
                "YARA not installed. "
                "Run: python -m pip install -r requirements.txt"
            )

        elif YARA_ERROR:

            self.status_variable.set(
                f"YARA unavailable: {YARA_ERROR}"
            )


    # ========================================================
    # SELECT FOLDER
    # ========================================================

    def select_folder(
        self
    ):

        if self.scan_button[
            "state"
        ] == "disabled":

            return


        folder = filedialog.askdirectory(
            title="Select folder to scan"
        )


        if not folder:

            return


        self.current_folder = folder


        self.clear_results()


        self.stop_event.clear()


        self.scan_button.config(
            state="disabled"
        )


        self.stop_button.config(
            state="normal"
        )


        self.progress.start(
            10
        )


        self.status_variable.set(
            f"Starting scan: {folder}"
        )


        # ----------------------------------------------------
        # Run scanner in background
        # ----------------------------------------------------

        scanner_thread = threading.Thread(
            target=self.scan_worker,
            args=(folder,),
            daemon=True
        )


        scanner_thread.start()


    # ========================================================
    # SCAN WORKER
    # ========================================================

    def scan_worker(
        self,
        folder
    ):

        try:

            scan_directory(
                folder,

                lambda result,
                       count,
                       threats,
                       errors:

                    self.events.put(
                        (
                            "result",
                            result,
                            count,
                            threats,
                            errors
                        )
                    ),

                lambda status:

                    self.events.put(
                        (
                            "status",
                            status
                        )
                    ),

                self.stop_event
            )


        except Exception as error:

            self.events.put(
                (
                    "fatal",
                    str(error)
                )
            )


        finally:

            self.events.put(
                (
                    "done",
                )
            )


    # ========================================================
    # PROCESS EVENTS
    # ========================================================

    def process_events(
        self
    ):

        try:

            while True:

                event = (
                    self.events.get_nowait()
                )


                event_type = event[0]


                # ------------------------------------------------
                # Result
                # ------------------------------------------------

                if event_type == "result":

                    (
                        _,
                        result,
                        count,
                        threats,
                        errors
                    ) = event


                    self.results.append(
                        result
                    )


                    item_id = self.tree.insert(
                        "",
                        "end",
                        values=(
                            result["status"],
                            result["path"],
                            result["detection"],
                            result["sha256"]
                        )
                    )


                    # Store result index
                    self.tree.set(
                        item_id,
                        "status",
                        result["status"]
                    )


                    self.summary_variable.set(
                        f"Files: {count} | "
                        f"Threats: {threats} | "
                        f"Errors: {errors}"
                    )


                # ------------------------------------------------
                # Status
                # ------------------------------------------------

                elif event_type == "status":

                    self.status_variable.set(
                        event[1]
                    )


                # ------------------------------------------------
                # Fatal
                # ------------------------------------------------

                elif event_type == "fatal":

                    messagebox.showerror(
                        "Scanner Error",
                        event[1]
                    )


                # ------------------------------------------------
                # Done
                # ------------------------------------------------

                elif event_type == "done":

                    self.progress.stop()


                    self.scan_button.config(
                        state="normal"
                    )


                    self.stop_button.config(
                        state="disabled"
                    )


                    if self.stop_event.is_set():

                        self.status_variable.set(
                            "Scan stopped."
                        )

                    else:

                        self.status_variable.set(
                            "Scan completed."
                        )


        except queue.Empty:

            pass


        self.after(
            100,
            self.process_events
        )


    # ========================================================
    # STOP SCAN
    # ========================================================

    def stop_scan(
        self
    ):

        self.stop_event.set()


        self.status_variable.set(
            "Stopping scan..."
        )


    # ========================================================
    # CLEAR RESULTS
    # ========================================================

    def clear_results(
        self
    ):

        for item in self.tree.get_children():

            self.tree.delete(
                item
            )


        self.results.clear()


        self.summary_variable.set(
            "Files: 0 | Threats: 0 | Errors: 0"
        )


    # ========================================================
    # GET SELECTED RESULTS
    # ========================================================

    def selected_results(
        self
    ):

        selected_items = (
            self.tree.selection()
        )


        selected_results = []


        for item in selected_items:

            values = self.tree.item(
                item,
                "values"
            )


            if not values:

                continue


            selected_results.append(
                {
                    "item": item,

                    "status":
                        values[0],

                    "path":
                        values[1],

                    "detection":
                        values[2],

                    "sha256":
                        values[3]
                }
            )


        return selected_results


    # ========================================================
    # QUARANTINE SELECTED
    # ========================================================

    def quarantine_selected(
        self
    ):

        selected = [

            item

            for item in self.selected_results()

            if item["status"] == "THREAT"

        ]


        if not selected:

            messagebox.showinfo(
                "Quarantine",
                "Select one or more THREAT rows first."
            )

            return


        confirmation = messagebox.askyesno(
            "Confirm Quarantine",
            (
                f"Move {len(selected)} "
                "detected file(s) to quarantine?"
            )
        )


        if not confirmation:

            return


        successful = 0


        for item in selected:

            success, message = quarantine_file(
                item["path"],
                item["detection"]
            )


            if success:

                successful += 1


                self.tree.item(
                    item["item"],
                    values=(
                        "QUARANTINED",
                        item["path"],
                        item["detection"],
                        item["sha256"]
                    )
                )


        messagebox.showinfo(
            "Quarantine Complete",
            (
                f"{successful}/"
                f"{len(selected)} "
                "file(s) quarantined."
            )
        )


    # ========================================================
    # RESTORE WINDOW
    # ========================================================

    def show_restore_window(
        self
    ):

        records = load_json(
            QUARANTINE_INDEX,
            {}
        )


        if not records:

            messagebox.showinfo(
                "Restore",
                "No quarantined files available."
            )

            return


        window = tk.Toplevel(
            self
        )


        window.title(
            "Pena Antivirus - Quarantine"
        )


        window.geometry(
            "1000x450"
        )


        window.transient(
            self
        )


        # ----------------------------------------------------
        # Table
        # ----------------------------------------------------

        tree = ttk.Treeview(
            window,
            columns=(
                "id",
                "original",
                "detection",
                "sha256"
            ),
            show="headings"
        )


        tree.heading(
            "id",
            text="ID"
        )


        tree.heading(
            "original",
            text="Original Path"
        )


        tree.heading(
            "detection",
            text="Detection"
        )


        tree.heading(
            "sha256",
            text="SHA-256"
        )


        tree.column(
            "id",
            width=230
        )


        tree.column(
            "original",
            width=330
        )


        tree.column(
            "detection",
            width=180
        )


        tree.column(
            "sha256",
            width=350
        )


        tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )


        # ----------------------------------------------------
        # Populate
        # ----------------------------------------------------

        for record_id, record in records.items():

            tree.insert(
                "",
                "end",
                values=(
                    record_id,

                    record[
                        "original_path"
                    ],

                    record[
                        "detection"
                    ],

                    record[
                        "sha256"
                    ]
                )
            )


        # ----------------------------------------------------
        # Restore function
        # ----------------------------------------------------

        def restore_selected():

            selected = tree.selection()


            if not selected:

                messagebox.showinfo(
                    "Restore",
                    "Select a quarantine record."
                )

                return


            item = selected[0]


            values = tree.item(
                item,
                "values"
            )


            record_id = values[0]


            success, message = restore_file(
                record_id
            )


            if success:

                tree.delete(
                    item
                )


                messagebox.showinfo(
                    "Restore Complete",
                    f"Restored to:\n{message}"
                )


            else:

                messagebox.showerror(
                    "Restore Failed",
                    message
                )


        ttk.Button(
            window,
            text="Restore Selected",
            command=restore_selected
        ).pack(
            pady=(0, 15)
        )


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":

    application = AntivirusApp()

    application.mainloop()