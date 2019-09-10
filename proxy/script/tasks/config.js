/**
 * Build configuration
 */

/**
 * We use this template to transform the "contentScriptParameters" object
 */
const contentScriptConfigurationTemplate = `{
    "nonce": "{{.Nonce}}",
    "cosmeticResult": {
        "elementHiding": {
            "generic": [
                {{range .Result.ElementHiding.Generic}}"{{js .}}",{{end}}
            ],
            "specific": [
                {{range .Result.ElementHiding.Specific}}"{{js .}}",{{end}}
            ],
            "genericExtCss": [
                {{range .Result.ElementHiding.GenericExtCSS}}"{{js .}}",{{end}}
            ],
            "specificExtCss": [
                {{range .Result.ElementHiding.SpecificExtCSS}}"{{js .}}",{{end}}
            ],
        },
        "css": {
            "generic": [
                {{range .Result.CSS.Generic}}"{{js .}}",{{end}}
            ],
            "specific": [
                {{range .Result.CSS.Specific}}"{{js .}}",{{end}}
            ],
            "genericExtCss": [
                {{range .Result.CSS.GenericExtCSS}}"{{js .}}",{{end}}
            ],
            "specificExtCss": [
                {{range .Result.CSS.SpecificExtCSS}}"{{js .}}",{{end}}
            ],
        },
        "js": {
            "generic": [
                {{range .Result.JS.Generic}}() => { {{.}} },{{end}}
            ],
            "specific": [
                {{range .Result.JS.Specific}}() => { {{.}} },{{end}}
            ],
        }
    }
}`;

module.exports = {
    outputDir: 'dist',
    fileName: 'content-script.js',

    /**
     * Generated file with the golang template
     */
    goTemplatePath: '../content_script_tmpl.go',

    /**
     * Name of the variable that will be replaced by a golang template.
     * See "generate.js" for more details on this.
     */
    contentScriptConfigurationName: 'contentScriptConfiguration',
    contentScriptConfigurationTemplate,
};
