rule FirstRule
{
    strings:
        $a = "cobalt strike"
    condition:
        $a
}

rule SecondRule
{
    strings:
        $b = "beacon"
    condition:
        $b
}
