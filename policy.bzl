"""Leverage Capirca to generate policies using a simple build rule."""

def aclgen_policy(name, src, defs, out):
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
            "$(execpath //capirca:aclgen)",
            "--base_directory=$$(dirname $$(dirname $(location " + src + ")))",
            "--policy_file=$(location " + src + ")",
            "--definitions_directory=$$(dirname $$(echo $(locations :" + name + "_defs_filegroup) | cut -d' ' -f1))",
            "--output_directory=$$(dirname $@)",
        ]) + "> $@",
        tools = ["//capirca:aclgen"],
    )
