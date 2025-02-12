@{
    # Exclude a bunch of things for now. We can iteratively remove these as we clean up the code.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSAvoidTrailingWhitespace'
    )
}