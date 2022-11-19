function sleep(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}
async function status() {
  counter = 0
  do {
    rss = null
    try {
      rss = rs.initiate({_id: "mongors",  members: [{_id: 0, host: "mongo"}]});
    } catch(e) {
      await sleep(1000);
    }
    counter += 1
  } while(rss == null && counter < 10);
  db = db.getSiblingDB("films_summary");
  await sleep(1000);
  db.createCollection("films_summary.reviews");
  await sleep(1000);
  db.createCollection("films_summary.email_notification");
  await sleep(1000);
  res = db.reviews.createIndex({"film_id" : 1, "user_id": 1} , {unique: true } );
  res = db.reviews.createIndex({"film_id" : 1} , { } );
  res = db.email_notification.createIndex({"notification_id" : 1} , { } );
  await sleep(1000);
}
status()

