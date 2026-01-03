package main

// importing packages:
// "log" logging messages to console
// "net/http" for creating web servers/handling HTTP requests
import (
    "context"
    "log"
    "net/http"
    "database/sql" // SQL db interface
    "strings"

    // sqlite3 driver
    _ "github.com/mattn/go-sqlite3"
	"The-ANISTAS-Project/internal/audit"
)

func main() {
	// Example usage in your main function:
	results := internal.PerformAudit(db)

	// Convert to OSCAL
	oscalData, err := internal.GenerateOscalSAR(results)
	if err != nil {
		log.Fatal(err)
	}

	// Output JSON
	jsonOutput, _ := internal.ToJSON(oscalData)
	fmt.Println(jsonOutput)

	// Connect to identifier.sqlite file
    // Use sql.Open with the sqlite3 driver and a DSN. The busy timeout helps avoid "database is locked" errors.
    db, err := sql.Open("sqlite3", "file:identifier.sqlite?_busy_timeout=5000&_fk=ON")
    if err != nil {
        log.Fatal(err) // stop if if the connection is unsuccessful
    }
    defer db.Close() // when the program exits the DB closes

    // For SQLite, it is usually best to keep max open conns small to avoid locks.
    db.SetMaxOpenConns(1)
    db.SetMaxIdleConns(1)

    // Verify the connection is usable with a short timeout.
    ctx, cancel := context.WithTimeout(context.Background(), 3_000_000_000) // 3s
    defer cancel()
    if err = db.PingContext(ctx); err != nil {
        log.Fatal(err)
    }

	sqlStmt := `CREATE TABLE IF NOT EXISTS activities (
    id INTEGER NOT NULL PRIMARY KEY,
    time TEXT, 
    description TEXT
	);`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Table 'activities' created and initialized")
    // service to respond to health checks,
    // and when any GET request is made to the /health path the function is executed
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
            w.Header().Set("Allow", http.MethodGet)
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        _, _ = w.Write([]byte("OK")) // responds "OK" if running and healthy
    } )
    // creates /activities path, to display activities
    http.HandleFunc("/activities", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
            w.Header().Set("Allow", http.MethodGet)
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        rows, err := db.Query("SELECT id, time, description FROM activities") // query the db
        if err != nil {
            http.Error(w, "DB error", http.StatusInternalServerError)
            return
        }
        defer rows.Close()
        var b strings.Builder
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        // initializing variables to display
        for rows.Next() {
            var id int
            var ts, description string
            err = rows.Scan(&id, &ts, &description)
            if err != nil {
                continue // this will skip over broken rows
            }
            b.WriteString("\t")
            b.WriteString(ts)
            b.WriteString("\t")
            b.WriteString(description)
            b.WriteString("\n")
        }
        if err = rows.Err(); err != nil {
            http.Error(w, "DB rows error", http.StatusInternalServerError)
            return
        }
        _, _ = w.Write([]byte(b.String()))
    })
    // display server start
    log.Println("Starting server on :8080")
    err = http.ListenAndServe(":8080", nil) // nil tells server to use default multiplexer
    if err != nil {
        log.Fatal(err) // if it crashes/fails it logs it and exits
    }
}