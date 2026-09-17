rule EICAR_Test_File
{
    meta:
        description = "Detects the EICAR antivirus test file"
        author = "Pena Antivirus"
        version = "1.0"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar
}