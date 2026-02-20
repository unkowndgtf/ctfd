const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./ctf.db');

db.serialize(() => {
  db.run('DELETE FROM banned_ips', [], function(err) {
    if (err) {
      console.error('Error unbanning:', err.message);
    } else {
      console.log('All IPs unbanned successfully!');
    }
  });
});

db.close();