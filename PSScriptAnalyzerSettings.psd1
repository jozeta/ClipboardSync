# PSScriptAnalyzer (app standards QA-LINT-1). CI lists errors and warnings and fails on errors.
#   Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
@{
    Severity     = @('Error', 'Warning')
    # The console log is the user interface of this script.
    # PSUseBOMForUnicodeEncodedFile: the script requires PowerShell 7, which reads UTF-8 without a BOM.
    ExcludeRules = @('PSAvoidUsingWriteHost', 'PSUseBOMForUnicodeEncodedFile')
}
