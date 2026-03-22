version       = "0.1.0"
author        = "Joel Lienhard"
description   = "A website for unbiased movie/tvshow suggestions based on overlaps with other users ratings"
license       = "MIT"
srcDir        = "src"
binDir        = "out"
bin           = @["server"]


requires "nim >= 2.2.6"
requires "fusion"
requires "nimja >= 0.10.0"
requires "unroll"
requires "webby"
requires "mummy"
requires "waterpark"
requires "checksums"
requires "jsony"
requires "jwt"


before build:
  exec "sassc src/style.sass out/static/style.css"