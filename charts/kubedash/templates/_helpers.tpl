{{- define "kubedash.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "kubedash.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kubedash.labels" -}}
app.kubernetes.io/name: {{ include "kubedash.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "kubedash.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubedash.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
