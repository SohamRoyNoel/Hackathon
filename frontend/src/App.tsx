import { useState } from 'react'
import './App.css'

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

interface Finding {
  ruleId: string
  severity: Severity
  title: string
  description: string
  line: number
  evidence: string
}

interface BlueTeamResult {
  outcome: boolean
  highestSeverity: Severity | null
  summary: Record<Severity, number>
  findings: Finding[]
  linesScanned: number
  note?: string
}

interface CreateUserResponse {
  message: string
  outcome?: boolean
  blueTeam?: BlueTeamResult
}

function App() {
  const [users, setUsers] = useState('')
  const [role, setRole] = useState('')
  const [ignoreDefaultRoleScanSkip, setIgnoreDefaultRoleScanSkip] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [responseMessage, setResponseMessage] = useState('')
  const [outcome, setOutcome] = useState<boolean | null>(null)
  const [blueTeam, setBlueTeam] = useState<BlueTeamResult | null>(null)

  const isFormComplete = users.trim().length > 0 && role !== ''

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    if (!isFormComplete) {
      return
    }

    setIsSubmitting(true)
    setResponseMessage('')
    setOutcome(null)
    setBlueTeam(null)

    try {
      const response = await fetch('http://localhost:3002/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userName: users,
          role: [role],
          shouldIncludeScan: ignoreDefaultRoleScanSkip,
        }),
      })

      if (!response.ok) {
        throw new Error(`Request failed with status ${response.status}`)
      }

      const data: CreateUserResponse = await response.json()
      const message = data?.message || JSON.stringify(data)
      setResponseMessage(message)
      setOutcome(typeof data?.outcome === 'boolean' ? data.outcome : null)
      setBlueTeam(data?.blueTeam ?? null)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      setResponseMessage(message)
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <main className="page-shell">
      <form className="form-card" onSubmit={handleSubmit}>
        <h1>Role Assignment</h1>

        <label className="field" htmlFor="users">
          <span>Users</span>
          <input
            id="users"
            name="users"
            type="text"
            value={users}
            onChange={(event) => setUsers(event.target.value)}
            placeholder="Enter user names"
          />
        </label>

        <label className="field" htmlFor="role">
          <span>Role</span>
          <select
            id="role"
            name="role"
            value={role}
            onChange={(event) => setRole(event.target.value)}
          >
            <option value="">Select role</option>
            <option value="Role001">Role001</option>
            <option value="Role002">Role002</option>
            <option value="Role003">Role003</option>
            <option value="Role004">Role004</option>
            <option value="Super_User">Super User</option>
          </select>
        </label>

        <label className="checkbox-row" htmlFor="ignoreDefaultRoleScanSkip">
          <input
            id="ignoreDefaultRoleScanSkip"
            name="ignoreDefaultRoleScanSkip"
            type="checkbox"
            checked={ignoreDefaultRoleScanSkip}
            onChange={(event) => setIgnoreDefaultRoleScanSkip(event.target.checked)}
          />
          <span>Ignore default role scan skip</span>
        </label>

        {isFormComplete && (
          <button type="submit" disabled={isSubmitting}>
            {isSubmitting ? 'Submitting...' : 'Submit'}
          </button>
        )}

        {responseMessage && (
          <p className={`response ${responseMessage === 'user already exists' ? 'error' : 'success'}`}>
            {responseMessage}
          </p>
        )}

        {outcome !== null && (
          <section className={`outcome-panel ${outcome ? 'danger' : 'safe'}`}>
            <div className="outcome-head">
              <span className="outcome-label">Blue team · dangerous event</span>
              <code className="outcome-value">outcome = {String(outcome)}</code>
            </div>
            <p className="outcome-verdict">
              {outcome
                ? 'Dangerous event detected in the scan report.'
                : 'No dangerous event detected in the scan report.'}
            </p>

            {blueTeam && (
              <>
                <p className="outcome-summary">
                  CRITICAL {blueTeam.summary.CRITICAL} · HIGH {blueTeam.summary.HIGH} ·
                  MEDIUM {blueTeam.summary.MEDIUM} · LOW {blueTeam.summary.LOW}
                  {' '}({blueTeam.linesScanned} lines scanned)
                </p>

                {blueTeam.findings.length > 0 && (
                  <ul className="finding-list">
                    {blueTeam.findings.map((finding, index) => (
                      <li
                        key={`${finding.ruleId}-${finding.line}-${index}`}
                        className={`finding sev-${finding.severity.toLowerCase()}`}
                      >
                        <div className="finding-top">
                          <span className="finding-sev">{finding.severity}</span>
                          <span className="finding-title">{finding.title}</span>
                          <span className="finding-line">L{finding.line}</span>
                        </div>
                        <p className="finding-desc">{finding.description}</p>
                        <code className="finding-evidence">{finding.evidence}</code>
                      </li>
                    ))}
                  </ul>
                )}

                {blueTeam.note && <p className="outcome-note">{blueTeam.note}</p>}
              </>
            )}
          </section>
        )}
      </form>
    </main>
  )
}

export default App
