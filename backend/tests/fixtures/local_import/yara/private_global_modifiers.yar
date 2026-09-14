global rule GlobalFileSizeLimit
{
    condition:
        filesize < 50MB
}

private rule PrivateHelper
{
    strings:
        $magic = { 4D 5A }
    condition:
        $magic at 0
}

rule MimikatzStrings
{
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii
        $s2 = "mimikatz" nocase
    condition:
        PrivateHelper and any of ($s*)
}
