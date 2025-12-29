{.experimental: "strictDefs".}
import std/[strformat, strutils, envvars, sysrand, osproc, streams, httpclient, base64, uri, importutils, macros]
import fusion/matching
import checksums/sha3
import db_connector/db_mysql
import prologue, prologue/middlewares/[staticfile, sessions/memorysession]
import nimja, jsony

setCurrentDir getAppDir()

const
  port = Port 8090
  publicHost =
    when defined(release): "https://tvsuggest.chol.foo"
    else: &"localhost:{port}"
  senderEmailAddress = "TV Suggest <noreply@tvsuggest.chol.foo>"

let db = open("localhost", getEnv"MYSQL_USER", getEnv"MYSQL_PASSWORD", getEnv"MYSQL_DATABASE")

let settings = newSettings(
  debug = not defined(release),
  port = port,
  address =
    when defined(release): "0.0.0.0"
    else: "127.0.0.1"
)
var app = newApp(settings)

app.use(staticFileMiddleware("static"))
app.use(sessionMiddleware(settings))


proc randomCode: string = base64.encode(urandom(24))

template respTemplate(name: static string, status = Http200): untyped =
  resp tmplf("templates/"&name&".nimja", baseDir = getScriptDir()), status

template serveStaticTemplate(name: static string): untyped =
  app.get("/"&name.replace("_", "/")) do(ctx {.inject.}: Context) {.async.}:
    respTemplate(name)

macro withUser(node: untyped): untyped =
  result = node
  let body = node[^1]
  let email = ident"email"
  result[^1] = quote do: 
    privateAccess Session
    if ctx.session.data.hasKey("user_email"):
      let `email` = ctx.session["user_email"]
      `body`
    else:
      resp redirect("/login")

proc sendMail(to: string, body: string) =
  # `body` is expected to contain missing headers (like subject) and body
  when defined(release):
    let p = startProcess("/usr/sbin/sendmail", args = ["-t", "-i"])
    let stdin = p.inputStream()
    stdin.writeLine("From: ", senderEmailAddress)
    stdin.writeLine("To: ", to)
    stdin.writeLine(body)
    close p
  else:
    echo "To: ", to
    echo body

template sendMailTmpl(to: string, tmpl: static string) =
  sendMail(to, &static(staticRead("email_templates/"&tmpl)))


app.registerErrorHandler(Http404) do(ctx: Context) {.async.}:
  const title = "404 Page not found"
  const msg = ""
  respTemplate "msg", Http404

app.registerErrorHandler(Http500) do(ctx: Context) {.async.}:
  const title = "500 Internal Server Error"
  const msg = "There was an unexpected server error."
  respTemplate "msg", Http500


serveStaticTemplate "login"

app.post("/login") do(ctx: Context) {.async.}:
  let email = ctx.getFormParams("email")
  let pw = ctx.getFormParams("password")
  let pwHash = db.getValue(
    sql"""
      SELECT pw_hash
      FROM users
      WHERE email = ? AND is_confirmed
    """,
    email
  )
  if pwHash == "":
    resp "No user found with this email address.", Http400
  elif $secureHash(Sha3_256, pw) != pwHash:
    resp "Wrong password.", Http400
  else:
    ctx.session["user_email"] = email
    resp ""

serveStaticTemplate "signup"

app.post("/signup") do(ctx: Context) {.async.}:
  let email = ctx.getFormParams("email")
  let pw = ctx.getFormParams("password")

  [@code, @confirmed] := db.getRow(sql"SELECT confirm_code, is_confirmed FROM users WHERE email = ?", email)

  if confirmed == "1":
    resp "A user with this email is already registered.", Http400

  else:
    if code == "":
      code = randomCode()
      db.exec(sql"""
        INSERT INTO users(email, pw_hash, confirm_code)
        VALUES(?, ?, ?)
      """,
        email, $secureHash(Sha3_256, pw), code
      )
    let confirmUrl = &"{publicHost}/signup/confirm/{encodeUrl(email)}/{encodeUrl(code)}"
    sendMailTmpl(email, "confirm_signup.txt")
    resp "Registration sent. You should recieve an email with a confirmation link."

app.get("/signup/confirm/{email}/{code}") do(ctx: Context) {.async.}:
  let email = ctx.getPathParams("email")
  let code = ctx.getPathParams("code")
  let correctCode = db.getValue(sql"SELECT confirm_code FROM users WHERE email = ?", email)
  let (title, msg) = 
    if correctCode == "":
      ("Error", "There is no user with this email address.")
    elif code != correctCode:
      ("Wrong Code", "The confirmation code is incorrect.")
    else:
      ("Registration Completed", "You are now registered and can log in.")

  db.exec(sql"UPDATE users SET is_confirmed = true WHERE email = ?", email)
  respTemplate "msg"

serveStaticTemplate "pwreset_request"

app.post("/pwreset/request") do(ctx: Context) {.async.}:
  let email = ctx.getFormParams("email")
  if db.getValue(sql"SELECT is_confirmed FROM users WHERE email = ?", email) != "1":
    resp "There is no user with this email address.", Http400
  else:
    let code = randomCode()
    db.exec(sql"UPDATE users SET confirm_code = ? WHERE email = ?", code, email)
    let resetUrl = &"{publicHost}/pwreset/{encodeUrl(email)}/{encodeUrl(code)}"
    sendMailTmpl(email, "pwreset.txt")
    resp "Reset link sent. You should recieve an email with a link to reset your password."

app.get("/pwreset/{email}/{code}") do(ctx: Context) {.async.}:
  echo "reset pw"
  let email = ctx.getPathParams("email")
  let code = ctx.getPathParams("code")
  respTemplate "pwreset"

app.post("/pwreset/{email}/{code}") do(ctx: Context) {.async.}:
  let email = ctx.getPathParams("email")
  let code = ctx.getPathParams("code")
  let pw = ctx.getFormParams("password")
  [@correctCode, @confirmed] := db.getRow(sql"SELECT confirm_code, is_confirmed FROM users WHERE email = ?", email)
  if confirmed != "1":
    resp "A user with this email is already registered.", Http400
  elif code != correctCode:
    resp "The confirmation code is incorrect.", Http400
  else:
    db.exec(sql"UPDATE users SET pw_hash = ? WHERE email = ?", $secureHash(Sha3_256, pw), email)
    resp "New password set successfully."


app.get("/") do(ctx: Context) {.withUser, async.}:
  respTemplate "home"


type Title = object
  id, kind, name, img, startYear: string 

proc parseHook(s: string, i: var int, title: var Title) =
  var d: tuple[
    id, `type`, primaryTitle: string,
    primaryImage: tuple[url: string],
    startYear: int
  ]
  parseHook(s, i, d)
  title = Title(
    id: d.id, kind: d.`type`, name: d.primaryTitle,
    img: d.primaryImage.url,
    startYear: if d.startYear == 0: "" else: $d.startYear
  )

const ratingOptions = {"bad": -1, "neutral": 0, "good": 1, "better": 2}

const movieDbApiUrl = "https://api.imdbapi.dev"
proc requestMovieDb(path: string): Future[tuple[code: HttpCode, body: string]] {.async.} =
  var client = newAsyncHttpClient()
  let resp = await client.get(movieDbApiUrl & path)
  result = (resp.code, await resp.bodyStream.readAll())
  close client

type MovieDbError = ref object of CatchableError
  code: HttpCode

template exitWith(error: MovieDbError): untyped =
  block:
    let e = error
    let msg: string
    if e.code == Http429:
      msg = "Sorry, there are too many requests. Please try again later."
    else:
      msg = "There was an unexpected server error."
      stderr.writeLine(e.msg)
    resp msg
    return

proc renderTitle(id: string, rating = none(int)): Future[string] {.async.} =
  let (code, body) = await requestMovieDb("/titles/" & encodeUrl(id))
  if code == Http200:
    let title = body.fromJson(Title)
    return tmplf("templates/title.nimja", baseDir = getScriptDir())
  else:
    raise MovieDbError(code: code, msg: body)

proc getRating(email, titleId: string): Option[int] =
  let s = db.getValue(sql"SELECT rating FROM user_ratings WHERE user_email = ? AND title_id = ?", email, titleId)
  if s == "": none(int)
  else: some(parseInt(s))

app.get("/my-ratings/{rating}") do(ctx: Context) {.withUser, async.}:
  let rating = parseInt(ctx.getPathParams("rating"))
  var body = ""
  for row in db.rows(
    sql"""
      SELECT title_id FROM user_ratings
      WHERE user_email = ? AND rating = ?
    """,
    email, rating
  ):
    try:
      body &= await renderTitle(row[0], some(rating))
    except MovieDbError as e:
      exitWith e
  resp body

app.post("/rate/{titleId}/{rating}") do(ctx: Context) {.withUser, async.}:
  let titleId = ctx.getPathParams("titleId")
  let rating = ctx.getPathParams("rating")
  if db.getValue(sql"SELECT 1 FROM user_ratings WHERE user_email = ? AND title_id = ?", email, titleId) == "1":
    db.exec(sql"UPDATE user_ratings SET rating = ? WHERE user_email = ? AND title_id = ?", rating, email, titleId)
  else:
    db.exec(sql"INSERT INTO user_ratings(user_email, title_id, rating) VALUES(?, ?, ?)", email, titleId, rating)

app.get("/search/{title}") do(ctx: Context) {.withUser, async.}:
  let title = ctx.getPathParams("title")
  let (code, body) = await requestMovieDb("/search/titles?query=" & encodeUrl(title))
  case code
  of Http200:
    let titles = body.fromJson(tuple[titles: seq[Title]]).titles
    var respBody = ""
    for title in titles:
      let rating = getRating(email, title.id)
      respBody &= tmplf("templates/title.nimja", baseDir = getScriptDir())
    resp respBody
  else:
    exitWith MovieDbError(code: code, msg: body)

app.get("/suggestions") do(ctx: Context) {.withUser, async.}:
  var body = ""
  for row in db.rows(
    sql"""
      WITH own_ratings AS (
        SELECT title_id, rating
        FROM user_ratings
        WHERE user_email = ? AND rating > 0
      ),
      subj_ratings AS (
        SELECT user_ratings.title_id, (own_ratings.rating * sum(user_ratings.rating)) AS rating
        FROM user_ratings
        INNER JOIN own_ratings
        WHERE user_ratings.title_id NOT IN (SELECT title_id FROM own_ratings)
        GROUP BY user_ratings.title_id
      )
      SELECT title_id
      FROM subj_ratings
      WHERE rating > 0
      ORDER BY rating
      LIMIT 40
    """,
    email
  ):
    try:
      body &= await renderTitle(row[0])
    except MovieDbError as e:
      exitWith e
  resp body


run app