{.experimental: "strictDefs".}
import std/[strformat, strutils, tables, json, envvars, sysrand, osproc, streams, httpclient, base64, times]
import fusion/matching
import checksums/sha3
import nimja, jsony, jwt, webby
import waterpark/postgres
import mummy, mummy/routers

setCurrentDir getAppDir()

const
  port = 8090
  host =
    when defined(release): "0.0.0.0"
    else: "127.0.0.1"
  publicHost =
    when defined(release): "https://tvsuggest.chol.foo"
    else: &"localhost:{port}"
  senderEmailAddress = "TV Suggest <noreply@tvsuggest.chol.foo>"

  jwtTokenName = "session"

let secret = getEnv"SECRET"


let db = newPostgresPool(4, "localhost", getEnv"DB_USER", getEnv"DB_PASS", getEnv"DB_NAME")
var router: Router
  

proc randomCode: string = base64.encode(urandom(24))

template respondTemplate(request: Request, name: static string) =
  request.respond(200, @{"Content-Type": "text/html; charset=utf-8"},
    tmplf("templates/"&name&".nimja", baseDir=getScriptDir()))

template serveTemplate(name: static string) =
  router.get("/"&name) do(request: Request):
    request.respondTemplate(name)

proc respondMsgPage(request: Request, title, msg: string) =
  request.respondTemplate("msg")


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


proc setJwtTokenCookie(email: string): string =
  var token = toJWT(%*{
    "header": {
      "alg": "HS256",
      "typ": "JWT"
    },
    "claims": {
      "email": email,
      "exp": (getTime() + 14.days).toUnix()
    }
  })
  {.gcsafe.}:
    token.sign(secret)
  &"{jwtTokenName}={token}; Path=/; HttpOnly; Secure; SameSite=Strict"

proc getEmailFormJwt(cookies: string): string =
  let cookies = cookies.split(";")
  for cookie in cookies:
    let cookie = cookie.strip
    if cookie.startsWith(jwtTokenName&"="):
      try:
        let token = cookie[len(jwtTokenName)+1 .. ^1].toJwt
        {.gcsafe.}:
          if token.verify(secret, HS256):
            return $token.claims["email"].node.str
      except: discard
  ""

template withUser =
  mixin request
  if "cookie" notin request.headers:
    request.respond(302, @{"Location": "/login"})
    return
  let email {.inject.} = getEmailFormJwt(request.headers["cookie"])
  if email == "":
    request.respond(302, @{
      "Location": "/login",
      "Set-Cookie": &"{jwtTokenName}=; Path=/; expires=Thu, Jan 01 1970 00:00:00 UTC"
    })
    return

proc postParams(request: Request): QueryParams {.inline.} =
  parseSearch(request.body)

template withCredentials =
  mixin request
  let params = request.postParams
  let email {.inject.} = params["email"]
  let password {.inject.} = params["password"]


router.get("/") do(request: Request):
  withUser
  request.respondTemplate("home")

serveTemplate("login")
router.post("/login") do(request: Request):
  withCredentials
  
  var pwHash = ""
  db.withConnection conn:
    pwHash = conn.getValue(
      sql"""
        SELECT pw_hash
        FROM users
        WHERE email = ? AND is_confirmed
      """,
      email
    )

  if pwHash == "":
    request.respond(400, body="No user found with this email address.")
  elif $secureHash(Sha3_256, password) != pwHash:
    request.respond(400, body="Wrong password.")
  else:
    request.respond(200, @{"Set-Cookie": setJwtTokenCookie(email)})

serveTemplate("signup")
router.post("/signup") do(request: Request):
  withCredentials

  db.withConnection conn:

    [@code, @confirmed] := conn.getRow(
      sql"SELECT confirm_code, is_confirmed FROM users WHERE email = ?", email)

    if confirmed == "1":
      request.respond(400, body="A user with this email is already registered.")

    else:
      if code == "":
        code = randomCode()
        conn.exec(sql"""
          INSERT INTO users(email, pw_hash, confirm_code)
          VALUES(?, ?, ?)
        """,
          email, $secureHash(Sha3_256, password), code
        )
      let confirmUrl = &"{publicHost}/signup/confirm/{encode(email)}/{encode(code)}"
      sendMailTmpl(email, "confirm_signup.txt")
      request.respond(200, body="Registration sent. You should recieve an email with a confirmation link.")

router.get("/signup/confirm/@email/@code") do(request: Request):
  let email = request.pathParams["email"].decode
  let code = request.pathParams["code"].decode

  db.withConnection conn:

    let correctCode = conn.getValue(sql"SELECT confirm_code FROM users WHERE email = ?", email)
    let (title, msg) = 
      if correctCode == "":
        ("Error", "There is no user with this email address.")
      elif code != correctCode:
        ("Wrong Code", "The confirmation code is incorrect.")
      else:
        ("Registration Completed", "You are now registered and can log in.")

    conn.exec(sql"UPDATE users SET is_confirmed = true WHERE email = ?", email)
    request.respondTemplate("msg")

serveTemplate("pwreset_request")
router.post("/pwreset/request") do(request: Request):
  let email = request.postParams["email"]
  db.withConnection conn:
    if conn.getValue(sql"SELECT is_confirmed FROM users WHERE email = ?", email) != "1":
      request.respond(400, body="There is no user with this email address.")
    else:
      let code = randomCode()
      conn.exec(sql"UPDATE users SET confirm_code = ? WHERE email = ?", code, email)
      let resetUrl = &"{publicHost}/pwreset/{encodeUrl(email)}/{encodeUrl(code)}"
      sendMailTmpl(email, "pwreset.txt")
      request.respond(200, body="Reset link sent. You should recieve an email with a link to reset your password.")

router.get("/pwreset/@email/@code") do(request: Request):
  let email = request.pathParams["email"]
  let code = request.pathParams["code"]
  request.respondTemplate("pwreset")

router.post("/pwreset/@email/@code") do(request: Request):
  let email = request.pathParams["email"]
  let code = request.pathParams["code"]
  let pw = request.postParams["password"]
  db.withConnection conn:
    [@correctCode, @confirmed] := conn.getRow(
      sql"SELECT confirm_code, is_confirmed FROM users WHERE email = ?",
      email
    )
    if confirmed != "1":
      request.respond(400, body="A user with this email is already registered.")
    elif code != correctCode:
      request.respond(400, body="The confirmation code is incorrect.")
    else:
      conn.exec(sql"UPDATE users SET pw_hash = ? WHERE email = ?", $secureHash(Sha3_256, pw), email)
      request.respond(200, body="New password set successfully.")


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
proc requestMovieDb(path: string): tuple[code: int, body: string] =
  var client = newHttpClient()
  let resp = client.get(movieDbApiUrl & path)
  result = (resp.code.int, resp.bodyStream.readAll())
  close client

type MovieDbError = ref object of CatchableError
  code: int

template exitWith(error: MovieDbError): untyped =
  mixin request
  let e = error
  let msg: string
  if e.code == 429:
    msg = "Sorry, there are too many requests. Please try again later."
  else:
    msg = "There was an unexpected server error."
    stderr.writeLine(e.msg)
  request.respond(200, body=msg)
  return

proc renderTitle(id: string, rating = none(int)): string =
  let (code, body) = requestMovieDb("/titles/" & encodeUrl(id))
  if code == 200:
    let title = body.fromJson(Title)
    return tmplf("templates/title.nimja", baseDir = getScriptDir())
  else:
    raise MovieDbError(code: code, msg: body)

proc getRating(email, titleId: string): Option[int] =
  var s = ""
  db.withConnection conn:
    s = conn.getValue(
      sql"SELECT rating FROM user_ratings WHERE user_email = ? AND title_id = ?",
      email, titleId
    )
  if s == "": none(int)
  else: some(parseInt(s))

router.get("/my-ratings/@rating") do(request: Request):
  withUser
  let rating = parseInt(request.pathParams["rating"])
  var body = ""
  var rows: seq[Row]
  db.withConnection conn:
    for row in conn.rows(
      sql"""
        SELECT title_id FROM user_ratings
        WHERE user_email = ? AND rating = ?
        ORDER BY updated_at DESC
      """,
      email, rating
    ):
      try:
        body &= renderTitle(row[0], some(rating))
      except MovieDbError as e:
        exitWith e
  request.respond(200, body=body)

router.post("/rate/@titleId/@rating") do(request: Request):
  withUser
  let titleId = request.pathParams["titleId"]
  let rating = request.pathParams["rating"]
  db.withConnection conn:
    if conn.getValue(sql"SELECT 1 FROM user_ratings WHERE user_email = ? AND title_id = ?", email, titleId) == "1":
      conn.exec(sql"""
        UPDATE user_ratings
        SET rating = ?, updated_at = now()
        WHERE user_email = ? AND title_id = ?
      """, rating, email, titleId)
    else:
      conn.exec(sql"""
        INSERT INTO user_ratings(user_email, title_id, rating)
        VALUES(?, ?, ?)""", email, titleId, rating)
  request.respond(200)

router.get("/search/@title") do(request: Request):
  withUser
  let title = request.pathParams["title"]
  let (code, body) = requestMovieDb("/search/titles?query=" & encodeUrl(title))
  case code
  of 200:
    let titles = body.fromJson(tuple[titles: seq[Title]]).titles
    var respBody = ""
    for title in titles:
      let rating = getRating(email, title.id)
      respBody &= tmplf("templates/title.nimja", baseDir = getScriptDir())
    request.respond(200, body=respBody)
  else:
    exitWith MovieDbError(code: code, msg: body)

router.get("/suggestions") do(request: Request):
  withUser
  var body = ""
  db.withConnection conn:
    for row in conn.rows(
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
        body &= renderTitle(row[0])
      except MovieDbError as e:
        exitWith e
  request.respond(200, body=body)


let server = newServer(router)
echo "Serving on " & host & ":" & $port
server.serve(Port(port), host)