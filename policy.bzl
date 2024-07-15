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

# Subset of suffixes that are actually defined in generator classes.
# Example of how to generate a starting point:
# perl -n -e'if(/ +SUFFIX = '"'"'(\.[a-z._]*)'"'"'$/) { my @path_parts = split "/", $ARGV ; my @base = split "\\.", $path_parts[1] ; print "    \"$base[0]\": \"$1\",\n"; }' lib/*.py
# More correct would be to also extract _PLATFORM from a generator class, and/or from aclgen.py.
#
# These would not be necessary if we accessed the passed policy files ahead of time, pushed them
# through Capirca's parser and determined the extension / suffix that way.
SUFFIXES = {
    "arista": ".eacl",
    "aruba": ".aacl",
    "brocade": ".bacl",
    "ciscoasa": ".asa",
    "cisconx": ".nxacl",
    "cisco": ".acl",
    "ciscoxr": ".xacl",
    "cloudarmor": ".gca",
    "esdn": ".esdn",
    "gce": ".gce",
    "gce_vpc_tf": ".tf.json",
    "gcp_hf": ".gcphf",
    "ipset": ".ips",
    "juniperevo": ".evojcl",
    "junipermsmpc": ".msmpc",
    "juniper": ".jcl",
    "junipersrx": ".srx",
    "k8s": ".yml",
    "maglev_protocols": ".maglev_protocols",
    "nftables": ".nft",
    "nsxt": ".nsxt",
    "nsxv": ".nsx",
    "openconfig": ".oacl",
    "packetfilter": ".pf",
    "pcap": ".pcap",
    "sonic": ".sonicacl",
    "speedway": ".ipt",
    "srxlo": ".jsl",
    "versa": ".vsp",
    "windows": ".bat",
    "paloaltofw": ".xml",
}

# Used if sample's base name does not match generator's filename.
GENERATORS_FOR_SAMPLES = {
    "arista_tp": "arista",
    "cisco_lab": "cisco",
    "mixed_gce": "gce",
    "mixed_gcp_hf": "gcp_hf",
    "juniper_loopback": "juniper",
    "juniperevo_loopback": "juniperevo",
    "msmpc": "junipermsmpc",
    "paloalto": "paloaltofw",
    "inet6_gce": "gce",
    "inet6_gcp_hf": "gcp_hf",
    "srx": "srxlo",
}

def aclgen_policies(srcs, defs):
    """Given a list of files, invoke aclgen_policy macro generating targets for all passed policies.

    Same defs will be applied to all files.

    Mainly intended for Capirca-internal use case of generating outputs for all sample policies.
    Input files are expected to conform to a structure resembling the sample policies to allow
    an extension to be determined based on the policy's filename.

    Args:
      name: name of a filegroup which will contain all the output filenames
      srcs: labels for input policies (particularly useful with glob)
      defs: additional includes passed into aclgen_policy() rule
    """

    outs = []

    for src in srcs:
        # Filenames: sample_nftables.pol, sample_nftables-dev.pol, sample_nsxt.pol...
        # (Basename without package name, directory name, ...)
        filename = str(src).split(":")[-1].split("/")[-1]

        # Target name: sample_nftables, sample_nftables_dev, sample_nsxt, ...
        # Assuming one dot in filename, remove extension and replace - with _.
        tgt_name = filename.split(".")[0].replace("-", "_")

        # Kind: nftables, nsxt, ...
        # Used to determine the file extension ("suffix"). Removes everything before the first
        # underscore (sample_nftables-dev.pol -> nftables-dev.pol), after a dash (nftables-dev.pol
        # -> sample_nftables), and everything after a dot (nsxv.pol -> nsxv).
        #
        # Extensions should *actually* come out of .pol"s platform -> generator class -> SUFFIX class
        # variable. However, this would require running bits of Capirca when generating targets
        # using Bazel impl, complicating the current approach of just having simple macros around
        # genrule and other simple macros.
        kind = filename.split("_", 1)[1].split("-")[0].split(".")[0]

        # Get a suffix, or find out a generator for a sample, then get the suffix.
        # Default to using .txt extension.
        suffix = SUFFIXES.get(kind, "")
        if not suffix:
            generator = GENERATORS_FOR_SAMPLES.get(kind, "")
            suffix = SUFFIXES.get(generator, ".txt")

        # out replaces .pol (or other extension) with the suffix determined above.
        out = filename.split(".")[0] + suffix

        outs.append(out)

        aclgen_policy(
            name = tgt_name,
            src = src,
            out = out,
            defs = defs,
        )

    native.filegroup(
        name = name,
        srcs = outs,
    )
