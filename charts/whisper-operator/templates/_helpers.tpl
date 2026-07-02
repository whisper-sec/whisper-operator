{{/* Chart name */}}
{{- define "whisper-operator.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified name */}}
{{- define "whisper-operator.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Common labels */}}
{{- define "whisper-operator.labels" -}}
app.kubernetes.io/name: {{ include "whisper-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Selector labels */}}
{{- define "whisper-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "whisper-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* ServiceAccount name */}}
{{- define "whisper-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "whisper-operator.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Webhook Service name (must match the cert SANs the operator mints) */}}
{{- define "whisper-operator.webhookService" -}}
{{- printf "%s-webhook" (include "whisper-operator.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Operator image ref */}}
{{- define "whisper-operator.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
