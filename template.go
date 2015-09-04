package oauthmw

import (
	"html/template"
	"net/http"
	"strings"
)

// Default Protected Page Template.
const DefaultProtectedPageTpl = `<!DOCTYPE html>
<html>
<head>
  <title>Login Required</title>
</head>
<body>
{{range $provName, $prov := .}}
  <a href="{{$prov}}">Login with {{$provName | title}}</a><br/>
{{else}}
  Sorry, no login options are currently available.
{{end}}
</body>
</html>`

// Template instance.
var protectedPageTpl = template.Must(template.New("oauthmw").Funcs(
	template.FuncMap{
		"title": strings.Title,
	},
).Parse(DefaultProtectedPageTpl))

// Default template handler.
func defaultTemplateFn(hrefs map[string]string, res http.ResponseWriter, req *http.Request) {
	protectedPageTpl.Execute(res, hrefs)
}
