# Procedure to include a file from the document root

proc tcl_include { filename } {
    source "$ENVS(DOCUMENT_ROOT)/$filename"
}
