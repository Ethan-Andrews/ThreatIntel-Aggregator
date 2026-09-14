import "pe"

rule SuspiciousPEHeader
{
    meta:
        description = "Detects a PE with an unusually small entry point section"
        author = "local-import fixture"
    condition:
        pe.number_of_sections < 3
}
