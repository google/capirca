"""Leverage Capirca to generate policies using a simple build rule."""

# copybara:strip_begin(BBCP is internal)
load("//devtools/bbcp/builddefs:build_defs.bzl", "generated_file")
# copybara:strip_end

# copybara:strip_begin(BBCP is internal)
def aclgen_policy(name, src, defs, out, tags):
    # copybara:strip_end_and_replace "def aclgen_policy(name, src, defs, out):"
    """Generate a Capirca policy for a given src.

    src must be exactly one file specifying the input policy.

    defs contains at least one file in the definitions directory. It is used to provide the
    directory where all definitions will be found. Only the first entry in the list is relevant.
    It is accepted as a list so that a glob can be provided without hardcoding a path.

    out must be a valid file path, but it must match what Capirca will output, and must be relative
    to current package where aclgen_policy will be used. It is used to compute the output directory
    that will be provided to Capirca, but does not affect the filename of the generated policy. This
    is required because different generators output files with different extensions. It must be
    exactly one file even if Capirca will generate multiple files; it may be replaced with a
    different argument that accepts multiple outputs in the future.

    # copybara:strip_begin(BBCP is internal)
    A BBCP rule scoped to 'presubmit' will be generated as well, so that a preview of the policy can
    be shown during code review.
    # copybara:strip_end
    """

    native.filegroup(
        name = name + "_defs_filegroup",
        srcs = defs,
    )

    native.genrule(
        name = name + "_genrule",
        srcs = [
            src,
            ":" + name + "_defs_filegroup",
        ],
        outs = [out],
        cmd = " ".join([
            # copybara:strip_begin(third_party is internal)
            "$(execpath //third_party/py/capirca:aclgen)",
            # copybara:strip_end_and_replace "$(execpath //capirca:aclgen)",
            "--base_directory=$$(dirname $$(dirname $(location " + src + ")))",
            "--policy_file=$(location " + src + ")",
            "--definitions_directory=$$(dirname $$(echo $(locations :" + name + "_defs_filegroup) | cut -d' ' -f1))",
            "--output_directory=$$(dirname $@)",
        ]) + "> $@",
        # copybara:strip_begin(third_party is internal)
        tools = ["//third_party/py/capirca:aclgen"],
        # copybara:strip_end_and_replace "tools = ["//capirca:aclgen"],",
    )

    # copybara:strip_begin(BBCP is internal)
    generated_file(
        name = name + "_bbcp",
        scopes = ["presubmit"],
        wrapped_target = ":" + name + "_genrule",
        tags = tags,
    )
    # copybara:strip_end
