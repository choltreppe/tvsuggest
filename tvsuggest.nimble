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
requires "prologue"
requires "redis"
requires "db_connector"
requires "checksums"
requires "jsony"


before build:
  exec "sassc src/style.sass out/static/style.css"