import { useState } from 'react'
import './App.css'

type IncidentAssessment = {
  incidentOccurred: boolean
  verdict: 'red' | 'green'
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical'
  title: string
  rationale: string
  evidence?: string[]
  degraded?: boolean
}

function App() {
  const [users, setUsers] = useState('')
  const [role, setRole] = useState('')
  const [ignoreDefaultRoleScanSkip, setIgnoreDefaultRoleScanSkip] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [responseMessage, setResponseMessage] = useState('')
  const [incident, setIncident] = useState<IncidentAssessment | null>(null)

  const isFormComplete = users.trim().length > 0 && role !== ''

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    if (!isFormComplete) {
      return
    }

    setIsSubmitting(true)
    setResponseMessage('')
    setIncident(null)

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

      const data = await response.json()
      const message = data?.message || JSON.stringify(data)
      setResponseMessage(message)
      setIncident(data?.incident ?? null)
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

        {incident && (
          <div className={`incident-card ${incident.verdict}`}>
            <div className="incident-head">
              <span className="incident-icon" aria-hidden="true">
                {incident.incidentOccurred ? '❌' : '✅'}
              </span>
              <div>
                <strong>
                  {incident.incidentOccurred
                    ? 'Security incident detected'
                    : 'No impactful security incident'}
                </strong>
                <div className="incident-title">{incident.title}</div>
              </div>
              <span className={`incident-sev sev-${incident.severity}`}>
                {incident.severity.toUpperCase()}
              </span>
            </div>
            {incident.rationale && (
              <p className="incident-rationale">{incident.rationale}</p>
            )}
            {incident.evidence && incident.evidence.length > 0 && (
              <ul className="incident-evidence">
                {incident.evidence.map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            )}
            {incident.degraded && (
              <p className="incident-degraded">
                ⚠️ Heuristic verdict (LLM judge unavailable).
              </p>
            )}
          </div>
        )}
      </form>
    </main>
  )
}

export default App
