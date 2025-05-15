export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Finding {
  severity:  Severity
  type:      'secret' | 'vulnerable-dep' | 'workflow-risk'
  file:      string
  line?:     number
  message:   string
  detail:    string
  fix:       string
}

export interface ScanReport {
  critical:       Finding[]
  high:           Finding[]
  medium:         Finding[]
  low:            Finding[]
  totalScanned:   number
  workflowFiles:  number
}
