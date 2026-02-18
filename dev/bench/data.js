window.BENCHMARK_DATA = {
  "lastUpdate": 1771392153257,
  "repoUrl": "https://github.com/perplext/nsd",
  "entries": {
    "Go Benchmark": [
      {
        "commit": {
          "author": {
            "email": "nick.consolo@gmail.com",
            "name": "Nick Consolo",
            "username": "perplext"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a2207af49dfc4726654490d8839c72a00ec436e9",
          "message": "ci: fix Benchmark git identity and Docker missing linker (#46)\n\n- Benchmark: set git user.name/email before commit to create gh-pages\n- Docker: add binutils package to provide ld linker for arm64 build",
          "timestamp": "2026-02-18T00:09:19-05:00",
          "tree_id": "c1f384e2004d09ada6bdd73715f26d9adec0cc40",
          "url": "https://github.com/perplext/nsd/commit/a2207af49dfc4726654490d8839c72a00ec436e9"
        },
        "date": 1771391615891,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkProcessTLSPacket",
            "value": 626.8,
            "unit": "ns/op\t     208 B/op\t       8 allocs/op",
            "extra": "1897820 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - ns/op",
            "value": 626.8,
            "unit": "ns/op",
            "extra": "1897820 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - B/op",
            "value": 208,
            "unit": "B/op",
            "extra": "1897820 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1897820 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes",
            "value": 7008,
            "unit": "ns/op\t    1588 B/op\t      93 allocs/op",
            "extra": "166042 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - ns/op",
            "value": 7008,
            "unit": "ns/op",
            "extra": "166042 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - B/op",
            "value": 1588,
            "unit": "B/op",
            "extra": "166042 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - allocs/op",
            "value": 93,
            "unit": "allocs/op",
            "extra": "166042 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint",
            "value": 160.6,
            "unit": "ns/op\t      60 B/op\t       0 allocs/op",
            "extra": "7512865 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - ns/op",
            "value": 160.6,
            "unit": "ns/op",
            "extra": "7512865 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - B/op",
            "value": 60,
            "unit": "B/op",
            "extra": "7512865 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "7512865 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint",
            "value": 253.5,
            "unit": "ns/op\t     121 B/op\t       0 allocs/op",
            "extra": "4803993 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - ns/op",
            "value": 253.5,
            "unit": "ns/op",
            "extra": "4803993 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - B/op",
            "value": 121,
            "unit": "B/op",
            "extra": "4803993 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4803993 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc",
            "value": 252.3,
            "unit": "ns/op\t      16 B/op\t       2 allocs/op",
            "extra": "4620349 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - ns/op",
            "value": 252.3,
            "unit": "ns/op",
            "extra": "4620349 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - B/op",
            "value": 16,
            "unit": "B/op",
            "extra": "4620349 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - allocs/op",
            "value": 2,
            "unit": "allocs/op",
            "extra": "4620349 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint",
            "value": 1366,
            "unit": "ns/op\t      1000 datapoints\t     183 B/op\t       0 allocs/op",
            "extra": "875955 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - ns/op",
            "value": 1366,
            "unit": "ns/op",
            "extra": "875955 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - datapoints",
            "value": 1000,
            "unit": "datapoints",
            "extra": "875955 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - B/op",
            "value": 183,
            "unit": "B/op",
            "extra": "875955 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "875955 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation",
            "value": 220.2,
            "unit": "ns/op\t     126 B/op\t       0 allocs/op",
            "extra": "5435954 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - ns/op",
            "value": 220.2,
            "unit": "ns/op",
            "extra": "5435954 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - B/op",
            "value": 126,
            "unit": "B/op",
            "extra": "5435954 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "5435954 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData",
            "value": 239836,
            "unit": "ns/op\t  106800 B/op\t      13 allocs/op",
            "extra": "4976 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - ns/op",
            "value": 239836,
            "unit": "ns/op",
            "extra": "4976 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - B/op",
            "value": 106800,
            "unit": "B/op",
            "extra": "4976 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - allocs/op",
            "value": 13,
            "unit": "allocs/op",
            "extra": "4976 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small",
            "value": 21735,
            "unit": "ns/op\t     724 B/op\t      59 allocs/op",
            "extra": "53764 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - ns/op",
            "value": 21735,
            "unit": "ns/op",
            "extra": "53764 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - B/op",
            "value": 724,
            "unit": "B/op",
            "extra": "53764 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53764 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium",
            "value": 21997,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "54702 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - ns/op",
            "value": 21997,
            "unit": "ns/op",
            "extra": "54702 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "54702 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54702 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large",
            "value": 22104,
            "unit": "ns/op\t     728 B/op\t      59 allocs/op",
            "extra": "54718 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - ns/op",
            "value": 22104,
            "unit": "ns/op",
            "extra": "54718 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - B/op",
            "value": 728,
            "unit": "B/op",
            "extra": "54718 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54718 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small",
            "value": 22343,
            "unit": "ns/op\t     703 B/op\t      60 allocs/op",
            "extra": "53973 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - ns/op",
            "value": 22343,
            "unit": "ns/op",
            "extra": "53973 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - B/op",
            "value": 703,
            "unit": "B/op",
            "extra": "53973 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53973 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium",
            "value": 22674,
            "unit": "ns/op\t     703 B/op\t      60 allocs/op",
            "extra": "54160 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - ns/op",
            "value": 22674,
            "unit": "ns/op",
            "extra": "54160 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - B/op",
            "value": 703,
            "unit": "B/op",
            "extra": "54160 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "54160 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large",
            "value": 22017,
            "unit": "ns/op\t     705 B/op\t      60 allocs/op",
            "extra": "48422 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - ns/op",
            "value": 22017,
            "unit": "ns/op",
            "extra": "48422 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - B/op",
            "value": 705,
            "unit": "B/op",
            "extra": "48422 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "48422 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small",
            "value": 22142,
            "unit": "ns/op\t     699 B/op\t      60 allocs/op",
            "extra": "53234 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - ns/op",
            "value": 22142,
            "unit": "ns/op",
            "extra": "53234 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - B/op",
            "value": 699,
            "unit": "B/op",
            "extra": "53234 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53234 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium",
            "value": 22146,
            "unit": "ns/op\t     705 B/op\t      60 allocs/op",
            "extra": "52748 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - ns/op",
            "value": 22146,
            "unit": "ns/op",
            "extra": "52748 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - B/op",
            "value": 705,
            "unit": "B/op",
            "extra": "52748 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52748 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large",
            "value": 22393,
            "unit": "ns/op\t     704 B/op\t      60 allocs/op",
            "extra": "53322 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - ns/op",
            "value": 22393,
            "unit": "ns/op",
            "extra": "53322 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - B/op",
            "value": 704,
            "unit": "B/op",
            "extra": "53322 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53322 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small",
            "value": 19943,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "60247 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - ns/op",
            "value": 19943,
            "unit": "ns/op",
            "extra": "60247 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "60247 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60247 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium",
            "value": 19823,
            "unit": "ns/op\t     535 B/op\t      57 allocs/op",
            "extra": "60044 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - ns/op",
            "value": 19823,
            "unit": "ns/op",
            "extra": "60044 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - B/op",
            "value": 535,
            "unit": "B/op",
            "extra": "60044 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60044 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large",
            "value": 19816,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "58729 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - ns/op",
            "value": 19816,
            "unit": "ns/op",
            "extra": "58729 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "58729 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58729 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small",
            "value": 20334,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "57940 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - ns/op",
            "value": 20334,
            "unit": "ns/op",
            "extra": "57940 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "57940 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57940 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium",
            "value": 20873,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "58854 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - ns/op",
            "value": 20873,
            "unit": "ns/op",
            "extra": "58854 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "58854 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58854 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large",
            "value": 20772,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "58299 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - ns/op",
            "value": 20772,
            "unit": "ns/op",
            "extra": "58299 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "58299 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58299 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small",
            "value": 20579,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "58464 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - ns/op",
            "value": 20579,
            "unit": "ns/op",
            "extra": "58464 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "58464 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58464 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium",
            "value": 20834,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58845 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - ns/op",
            "value": 20834,
            "unit": "ns/op",
            "extra": "58845 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58845 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58845 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large",
            "value": 20576,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "58611 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - ns/op",
            "value": 20576,
            "unit": "ns/op",
            "extra": "58611 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "58611 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58611 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small",
            "value": 19607,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "59500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - ns/op",
            "value": 19607,
            "unit": "ns/op",
            "extra": "59500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "59500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium",
            "value": 19455,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "60108 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - ns/op",
            "value": 19455,
            "unit": "ns/op",
            "extra": "60108 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "60108 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60108 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large",
            "value": 19959,
            "unit": "ns/op\t     537 B/op\t      57 allocs/op",
            "extra": "59782 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - ns/op",
            "value": 19959,
            "unit": "ns/op",
            "extra": "59782 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - B/op",
            "value": 537,
            "unit": "B/op",
            "extra": "59782 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59782 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small",
            "value": 20234,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "58052 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - ns/op",
            "value": 20234,
            "unit": "ns/op",
            "extra": "58052 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "58052 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58052 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium",
            "value": 20096,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58332 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - ns/op",
            "value": 20096,
            "unit": "ns/op",
            "extra": "58332 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58332 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58332 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large",
            "value": 20219,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58016 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - ns/op",
            "value": 20219,
            "unit": "ns/op",
            "extra": "58016 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58016 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58016 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small",
            "value": 20115,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "58147 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - ns/op",
            "value": 20115,
            "unit": "ns/op",
            "extra": "58147 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "58147 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58147 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium",
            "value": 20095,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "58124 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - ns/op",
            "value": 20095,
            "unit": "ns/op",
            "extra": "58124 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "58124 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58124 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large",
            "value": 20291,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "58045 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - ns/op",
            "value": 20291,
            "unit": "ns/op",
            "extra": "58045 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "58045 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58045 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration",
            "value": 5.637,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "212527306 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - ns/op",
            "value": 5.637,
            "unit": "ns/op",
            "extra": "212527306 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "212527306 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "212527306 times\n4 procs"
          },
          {
            "name": "BenchmarkInterpolation",
            "value": 1e-7,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkInterpolation - ns/op",
            "value": 1e-7,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkInterpolation - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkInterpolation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling",
            "value": 0.0000177,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling - ns/op",
            "value": 0.0000177,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2",
            "value": 39618,
            "unit": "ns/op\t    1364 B/op\t     114 allocs/op",
            "extra": "30120 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - ns/op",
            "value": 39618,
            "unit": "ns/op",
            "extra": "30120 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - B/op",
            "value": 1364,
            "unit": "B/op",
            "extra": "30120 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30120 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4",
            "value": 39737,
            "unit": "ns/op\t    1359 B/op\t     114 allocs/op",
            "extra": "30081 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - ns/op",
            "value": 39737,
            "unit": "ns/op",
            "extra": "30081 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - B/op",
            "value": 1359,
            "unit": "B/op",
            "extra": "30081 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30081 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8",
            "value": 39743,
            "unit": "ns/op\t    1360 B/op\t     114 allocs/op",
            "extra": "30045 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - ns/op",
            "value": 39743,
            "unit": "ns/op",
            "extra": "30045 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - B/op",
            "value": 1360,
            "unit": "B/op",
            "extra": "30045 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30045 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1m0s",
            "value": 4e-7,
            "unit": "ns/op\t        70.00 datapoints\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1m0s - ns/op",
            "value": 4e-7,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1m0s - datapoints",
            "value": 70,
            "unit": "datapoints",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1m0s - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1m0s - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1h0m0s",
            "value": 5e-7,
            "unit": "ns/op\t      3610 datapoints\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1h0m0s - ns/op",
            "value": 5e-7,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1h0m0s - datapoints",
            "value": 3610,
            "unit": "datapoints",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1h0m0s - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1h0m0s - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s",
            "value": 5e-7,
            "unit": "ns/op\t      3610 datapoints\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s - ns/op",
            "value": 5e-7,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s - datapoints",
            "value": 3610,
            "unit": "datapoints",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess",
            "value": 21643,
            "unit": "ns/op\t   53134 B/op\t      37 allocs/op",
            "extra": "55428 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - ns/op",
            "value": 21643,
            "unit": "ns/op",
            "extra": "55428 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - B/op",
            "value": 53134,
            "unit": "B/op",
            "extra": "55428 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "55428 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation",
            "value": 55.54,
            "unit": "ns/op\t        32.00 bytes/point\t       0 B/op\t       0 allocs/op",
            "extra": "21670555 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - ns/op",
            "value": 55.54,
            "unit": "ns/op",
            "extra": "21670555 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - bytes/point",
            "value": 32,
            "unit": "bytes/point",
            "extra": "21670555 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21670555 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21670555 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData",
            "value": 258322,
            "unit": "ns/op\t  123584 B/op\t      19 allocs/op",
            "extra": "4402 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - ns/op",
            "value": 258322,
            "unit": "ns/op",
            "extra": "4402 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - B/op",
            "value": 123584,
            "unit": "B/op",
            "extra": "4402 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - allocs/op",
            "value": 19,
            "unit": "allocs/op",
            "extra": "4402 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing",
            "value": 5611,
            "unit": "ns/op\t 213172000 packets/op\t       0 B/op\t       0 allocs/op",
            "extra": "213172 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - ns/op",
            "value": 5611,
            "unit": "ns/op",
            "extra": "213172 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - packets/op",
            "value": 213172000,
            "unit": "packets/op",
            "extra": "213172 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "213172 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "213172 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit",
            "value": 2.508,
            "unit": "ns/op\t       100.0 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "480907095 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - ns/op",
            "value": 2.508,
            "unit": "ns/op",
            "extra": "480907095 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allowed%",
            "value": 100,
            "unit": "allowed%",
            "extra": "480907095 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "480907095 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "480907095 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS",
            "value": 118,
            "unit": "ns/op\t         0.1278 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10168921 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - ns/op",
            "value": 118,
            "unit": "ns/op",
            "extra": "10168921 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allowed%",
            "value": 0.1278,
            "unit": "allowed%",
            "extra": "10168921 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10168921 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10168921 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS",
            "value": 117.9,
            "unit": "ns/op\t         1.277 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10159892 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - ns/op",
            "value": 117.9,
            "unit": "ns/op",
            "extra": "10159892 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allowed%",
            "value": 1.277,
            "unit": "allowed%",
            "extra": "10159892 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10159892 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10159892 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS",
            "value": 118.9,
            "unit": "ns/op\t        12.87 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10202749 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - ns/op",
            "value": 118.9,
            "unit": "ns/op",
            "extra": "10202749 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allowed%",
            "value": 12.87,
            "unit": "allowed%",
            "extra": "10202749 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10202749 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10202749 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool",
            "value": 324.3,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "3694077 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - ns/op",
            "value": 324.3,
            "unit": "ns/op",
            "extra": "3694077 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "3694077 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "3694077 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool",
            "value": 2478,
            "unit": "ns/op\t   14560 B/op\t       1 allocs/op",
            "extra": "449012 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - ns/op",
            "value": 2478,
            "unit": "ns/op",
            "extra": "449012 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - B/op",
            "value": 14560,
            "unit": "B/op",
            "extra": "449012 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "449012 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController",
            "value": 336.7,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3563965 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - ns/op",
            "value": 336.7,
            "unit": "ns/op",
            "extra": "3563965 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3563965 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3563965 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64",
            "value": 5.298,
            "unit": "ns/op\t12080.08 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226161993 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - ns/op",
            "value": 5.298,
            "unit": "ns/op",
            "extra": "226161993 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - MB/s",
            "value": 12080.08,
            "unit": "MB/s",
            "extra": "226161993 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226161993 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226161993 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256",
            "value": 5.303,
            "unit": "ns/op\t48275.92 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226019332 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - ns/op",
            "value": 5.303,
            "unit": "ns/op",
            "extra": "226019332 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - MB/s",
            "value": 48275.92,
            "unit": "MB/s",
            "extra": "226019332 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226019332 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226019332 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512",
            "value": 5.301,
            "unit": "ns/op\t96590.60 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "225569362 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - ns/op",
            "value": 5.301,
            "unit": "ns/op",
            "extra": "225569362 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - MB/s",
            "value": 96590.6,
            "unit": "MB/s",
            "extra": "225569362 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "225569362 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "225569362 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024",
            "value": 5.298,
            "unit": "ns/op\t193275.44 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226675677 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - ns/op",
            "value": 5.298,
            "unit": "ns/op",
            "extra": "226675677 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - MB/s",
            "value": 193275.44,
            "unit": "MB/s",
            "extra": "226675677 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226675677 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226675677 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500",
            "value": 5.303,
            "unit": "ns/op\t282836.88 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226573600 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - ns/op",
            "value": 5.303,
            "unit": "ns/op",
            "extra": "226573600 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - MB/s",
            "value": 282836.88,
            "unit": "MB/s",
            "extra": "226573600 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226573600 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226573600 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000",
            "value": 5.304,
            "unit": "ns/op\t1696957.32 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226617853 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - ns/op",
            "value": 5.304,
            "unit": "ns/op",
            "extra": "226617853 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - MB/s",
            "value": 1696957.32,
            "unit": "MB/s",
            "extra": "226617853 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226617853 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226617853 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline",
            "value": 54616,
            "unit": "ns/op\t         0 MB/op\t       0 B/op\t       0 allocs/op",
            "extra": "21890 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - ns/op",
            "value": 54616,
            "unit": "ns/op",
            "extra": "21890 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - MB/op",
            "value": 0,
            "unit": "MB/op",
            "extra": "21890 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21890 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21890 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple",
            "value": 90.4,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "13190575 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - ns/op",
            "value": 90.4,
            "unit": "ns/op",
            "extra": "13190575 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "13190575 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "13190575 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID",
            "value": 274.6,
            "unit": "ns/op\t      61 B/op\t       3 allocs/op",
            "extra": "4388176 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - ns/op",
            "value": 274.6,
            "unit": "ns/op",
            "extra": "4388176 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - B/op",
            "value": 61,
            "unit": "B/op",
            "extra": "4388176 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "4388176 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket",
            "value": 266.8,
            "unit": "ns/op\t    3432 B/op\t       0 allocs/op",
            "extra": "4937025 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - ns/op",
            "value": 266.8,
            "unit": "ns/op",
            "extra": "4937025 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - B/op",
            "value": 3432,
            "unit": "B/op",
            "extra": "4937025 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4937025 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small",
            "value": 22188,
            "unit": "ns/op\t     723 B/op\t      59 allocs/op",
            "extra": "53515 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - ns/op",
            "value": 22188,
            "unit": "ns/op",
            "extra": "53515 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - B/op",
            "value": 723,
            "unit": "B/op",
            "extra": "53515 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53515 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium",
            "value": 22546,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "53677 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - ns/op",
            "value": 22546,
            "unit": "ns/op",
            "extra": "53677 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "53677 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53677 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large",
            "value": 22204,
            "unit": "ns/op\t     724 B/op\t      59 allocs/op",
            "extra": "54008 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - ns/op",
            "value": 22204,
            "unit": "ns/op",
            "extra": "54008 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - B/op",
            "value": 724,
            "unit": "B/op",
            "extra": "54008 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54008 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small",
            "value": 20374,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "59418 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - ns/op",
            "value": 20374,
            "unit": "ns/op",
            "extra": "59418 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "59418 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59418 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium",
            "value": 20200,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "59234 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - ns/op",
            "value": 20200,
            "unit": "ns/op",
            "extra": "59234 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "59234 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59234 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large",
            "value": 20243,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "58744 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - ns/op",
            "value": 20243,
            "unit": "ns/op",
            "extra": "58744 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "58744 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58744 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small",
            "value": 20096,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "59385 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - ns/op",
            "value": 20096,
            "unit": "ns/op",
            "extra": "59385 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "59385 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59385 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium",
            "value": 20066,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "58846 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - ns/op",
            "value": 20066,
            "unit": "ns/op",
            "extra": "58846 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "58846 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58846 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large",
            "value": 20144,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58890 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - ns/op",
            "value": 20144,
            "unit": "ns/op",
            "extra": "58890 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58890 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58890 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix",
            "value": 42088,
            "unit": "ns/op\t   28459 B/op\t     331 allocs/op",
            "extra": "27295 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - ns/op",
            "value": 42088,
            "unit": "ns/op",
            "extra": "27295 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - B/op",
            "value": 28459,
            "unit": "B/op",
            "extra": "27295 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - allocs/op",
            "value": 331,
            "unit": "allocs/op",
            "extra": "27295 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap",
            "value": 6143,
            "unit": "ns/op\t    3568 B/op\t      49 allocs/op",
            "extra": "190354 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - ns/op",
            "value": 6143,
            "unit": "ns/op",
            "extra": "190354 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - B/op",
            "value": 3568,
            "unit": "B/op",
            "extra": "190354 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "190354 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer",
            "value": 9617,
            "unit": "ns/op\t    7257 B/op\t      34 allocs/op",
            "extra": "124342 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - ns/op",
            "value": 9617,
            "unit": "ns/op",
            "extra": "124342 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - B/op",
            "value": 7257,
            "unit": "B/op",
            "extra": "124342 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - allocs/op",
            "value": 34,
            "unit": "allocs/op",
            "extra": "124342 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey",
            "value": 2368,
            "unit": "ns/op\t    1400 B/op\t      27 allocs/op",
            "extra": "459856 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - ns/op",
            "value": 2368,
            "unit": "ns/op",
            "extra": "459856 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - B/op",
            "value": 1400,
            "unit": "B/op",
            "extra": "459856 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "459856 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial",
            "value": 16463,
            "unit": "ns/op\t   16466 B/op\t      98 allocs/op",
            "extra": "71659 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - ns/op",
            "value": 16463,
            "unit": "ns/op",
            "extra": "71659 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - B/op",
            "value": 16466,
            "unit": "B/op",
            "extra": "71659 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - allocs/op",
            "value": 98,
            "unit": "allocs/op",
            "extra": "71659 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor",
            "value": 8.757,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "137256990 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - ns/op",
            "value": 8.757,
            "unit": "ns/op",
            "extra": "137256990 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "137256990 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "137256990 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor",
            "value": 24.18,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "49697108 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - ns/op",
            "value": 24.18,
            "unit": "ns/op",
            "extra": "49697108 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "49697108 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "49697108 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex",
            "value": 36.19,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "32439741 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - ns/op",
            "value": 36.19,
            "unit": "ns/op",
            "extra": "32439741 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "32439741 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "32439741 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow",
            "value": 6.609,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "177675696 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - ns/op",
            "value": 6.609,
            "unit": "ns/op",
            "extra": "177675696 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "177675696 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "177675696 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse",
            "value": 18.59,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "64582665 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - ns/op",
            "value": 18.59,
            "unit": "ns/op",
            "extra": "64582665 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "64582665 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "64582665 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire",
            "value": 5.924,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "202692812 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - ns/op",
            "value": 5.924,
            "unit": "ns/op",
            "extra": "202692812 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "202692812 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "202692812 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix",
            "value": 3.747,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "320633008 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - ns/op",
            "value": 3.747,
            "unit": "ns/op",
            "extra": "320633008 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "320633008 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "320633008 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave",
            "value": 32.49,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "36685797 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - ns/op",
            "value": 32.49,
            "unit": "ns/op",
            "extra": "36685797 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "36685797 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "36685797 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle",
            "value": 3.739,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "321136197 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - ns/op",
            "value": 3.739,
            "unit": "ns/op",
            "extra": "321136197 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "321136197 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "321136197 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10",
            "value": 102883,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10 - ns/op",
            "value": 102883,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10 - B/op",
            "value": 5176,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10 - allocs/op",
            "value": 196,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100",
            "value": 103984,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - ns/op",
            "value": 103984,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - B/op",
            "value": 5176,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - allocs/op",
            "value": 196,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000",
            "value": 102676,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000 - ns/op",
            "value": 102676,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000 - B/op",
            "value": 5176,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000 - allocs/op",
            "value": 196,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate",
            "value": 442.3,
            "unit": "ns/op\t     229 B/op\t       3 allocs/op",
            "extra": "2686449 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - ns/op",
            "value": 442.3,
            "unit": "ns/op",
            "extra": "2686449 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - B/op",
            "value": 229,
            "unit": "B/op",
            "extra": "2686449 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2686449 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2",
            "value": 9003,
            "unit": "ns/op\t   17464 B/op\t      77 allocs/op",
            "extra": "125954 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - ns/op",
            "value": 9003,
            "unit": "ns/op",
            "extra": "125954 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - B/op",
            "value": 17464,
            "unit": "B/op",
            "extra": "125954 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - allocs/op",
            "value": 77,
            "unit": "allocs/op",
            "extra": "125954 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3",
            "value": 24724,
            "unit": "ns/op\t   47576 B/op\t     200 allocs/op",
            "extra": "48453 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - ns/op",
            "value": 24724,
            "unit": "ns/op",
            "extra": "48453 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - B/op",
            "value": 47576,
            "unit": "B/op",
            "extra": "48453 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - allocs/op",
            "value": 200,
            "unit": "allocs/op",
            "extra": "48453 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4",
            "value": 35696,
            "unit": "ns/op\t   69816 B/op\t     295 allocs/op",
            "extra": "33579 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - ns/op",
            "value": 35696,
            "unit": "ns/op",
            "extra": "33579 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - B/op",
            "value": 69816,
            "unit": "B/op",
            "extra": "33579 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - allocs/op",
            "value": 295,
            "unit": "allocs/op",
            "extra": "33579 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "perplext",
            "username": "perplext"
          },
          "committer": {
            "name": "perplext",
            "username": "perplext"
          },
          "id": "8bef858766e0d3d1464d4df6efc57e0efbff93cd",
          "message": "ci: fix Benchmark checkout and Docker arm64 build",
          "timestamp": "2026-02-18T05:09:23Z",
          "url": "https://github.com/perplext/nsd/pull/47/commits/8bef858766e0d3d1464d4df6efc57e0efbff93cd"
        },
        "date": 1771392152819,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkProcessTLSPacket",
            "value": 591.3,
            "unit": "ns/op\t     208 B/op\t       8 allocs/op",
            "extra": "2006080 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - ns/op",
            "value": 591.3,
            "unit": "ns/op",
            "extra": "2006080 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - B/op",
            "value": 208,
            "unit": "B/op",
            "extra": "2006080 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "2006080 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes",
            "value": 6974,
            "unit": "ns/op\t    1588 B/op\t      93 allocs/op",
            "extra": "171930 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - ns/op",
            "value": 6974,
            "unit": "ns/op",
            "extra": "171930 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - B/op",
            "value": 1588,
            "unit": "B/op",
            "extra": "171930 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - allocs/op",
            "value": 93,
            "unit": "allocs/op",
            "extra": "171930 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint",
            "value": 160.3,
            "unit": "ns/op\t      60 B/op\t       0 allocs/op",
            "extra": "7501197 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - ns/op",
            "value": 160.3,
            "unit": "ns/op",
            "extra": "7501197 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - B/op",
            "value": 60,
            "unit": "B/op",
            "extra": "7501197 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "7501197 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint",
            "value": 256.8,
            "unit": "ns/op\t     121 B/op\t       0 allocs/op",
            "extra": "4835606 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - ns/op",
            "value": 256.8,
            "unit": "ns/op",
            "extra": "4835606 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - B/op",
            "value": 121,
            "unit": "B/op",
            "extra": "4835606 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4835606 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc",
            "value": 251.9,
            "unit": "ns/op\t      16 B/op\t       2 allocs/op",
            "extra": "4742479 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - ns/op",
            "value": 251.9,
            "unit": "ns/op",
            "extra": "4742479 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - B/op",
            "value": 16,
            "unit": "B/op",
            "extra": "4742479 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - allocs/op",
            "value": 2,
            "unit": "allocs/op",
            "extra": "4742479 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint",
            "value": 1364,
            "unit": "ns/op\t      1000 datapoints\t     183 B/op\t       0 allocs/op",
            "extra": "867526 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - ns/op",
            "value": 1364,
            "unit": "ns/op",
            "extra": "867526 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - datapoints",
            "value": 1000,
            "unit": "datapoints",
            "extra": "867526 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - B/op",
            "value": 183,
            "unit": "B/op",
            "extra": "867526 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "867526 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation",
            "value": 219.1,
            "unit": "ns/op\t     126 B/op\t       0 allocs/op",
            "extra": "5423635 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - ns/op",
            "value": 219.1,
            "unit": "ns/op",
            "extra": "5423635 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - B/op",
            "value": 126,
            "unit": "B/op",
            "extra": "5423635 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "5423635 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData",
            "value": 238977,
            "unit": "ns/op\t  106800 B/op\t      13 allocs/op",
            "extra": "4735 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - ns/op",
            "value": 238977,
            "unit": "ns/op",
            "extra": "4735 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - B/op",
            "value": 106800,
            "unit": "B/op",
            "extra": "4735 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - allocs/op",
            "value": 13,
            "unit": "allocs/op",
            "extra": "4735 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small",
            "value": 21883,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "53911 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - ns/op",
            "value": 21883,
            "unit": "ns/op",
            "extra": "53911 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "53911 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53911 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium",
            "value": 22237,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "54776 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - ns/op",
            "value": 22237,
            "unit": "ns/op",
            "extra": "54776 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "54776 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54776 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large",
            "value": 21923,
            "unit": "ns/op\t     729 B/op\t      59 allocs/op",
            "extra": "54465 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - ns/op",
            "value": 21923,
            "unit": "ns/op",
            "extra": "54465 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - B/op",
            "value": 729,
            "unit": "B/op",
            "extra": "54465 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54465 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small",
            "value": 22317,
            "unit": "ns/op\t     703 B/op\t      60 allocs/op",
            "extra": "54194 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - ns/op",
            "value": 22317,
            "unit": "ns/op",
            "extra": "54194 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - B/op",
            "value": 703,
            "unit": "B/op",
            "extra": "54194 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "54194 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium",
            "value": 22431,
            "unit": "ns/op\t     702 B/op\t      60 allocs/op",
            "extra": "54447 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - ns/op",
            "value": 22431,
            "unit": "ns/op",
            "extra": "54447 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - B/op",
            "value": 702,
            "unit": "B/op",
            "extra": "54447 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "54447 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large",
            "value": 22153,
            "unit": "ns/op\t     705 B/op\t      60 allocs/op",
            "extra": "54217 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - ns/op",
            "value": 22153,
            "unit": "ns/op",
            "extra": "54217 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - B/op",
            "value": 705,
            "unit": "B/op",
            "extra": "54217 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "54217 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small",
            "value": 21992,
            "unit": "ns/op\t     701 B/op\t      60 allocs/op",
            "extra": "53365 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - ns/op",
            "value": 21992,
            "unit": "ns/op",
            "extra": "53365 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - B/op",
            "value": 701,
            "unit": "B/op",
            "extra": "53365 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53365 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium",
            "value": 21984,
            "unit": "ns/op\t     703 B/op\t      60 allocs/op",
            "extra": "53384 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - ns/op",
            "value": 21984,
            "unit": "ns/op",
            "extra": "53384 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - B/op",
            "value": 703,
            "unit": "B/op",
            "extra": "53384 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53384 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large",
            "value": 22744,
            "unit": "ns/op\t     703 B/op\t      60 allocs/op",
            "extra": "53281 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - ns/op",
            "value": 22744,
            "unit": "ns/op",
            "extra": "53281 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - B/op",
            "value": 703,
            "unit": "B/op",
            "extra": "53281 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53281 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small",
            "value": 20094,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "60283 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - ns/op",
            "value": 20094,
            "unit": "ns/op",
            "extra": "60283 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "60283 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60283 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium",
            "value": 19801,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "60295 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - ns/op",
            "value": 19801,
            "unit": "ns/op",
            "extra": "60295 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "60295 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60295 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large",
            "value": 20072,
            "unit": "ns/op\t     537 B/op\t      57 allocs/op",
            "extra": "58410 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - ns/op",
            "value": 20072,
            "unit": "ns/op",
            "extra": "58410 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - B/op",
            "value": 537,
            "unit": "B/op",
            "extra": "58410 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58410 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small",
            "value": 20195,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "57553 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - ns/op",
            "value": 20195,
            "unit": "ns/op",
            "extra": "57553 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "57553 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57553 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium",
            "value": 20233,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "55606 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - ns/op",
            "value": 20233,
            "unit": "ns/op",
            "extra": "55606 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "55606 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "55606 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large",
            "value": 20783,
            "unit": "ns/op\t     544 B/op\t      58 allocs/op",
            "extra": "57133 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - ns/op",
            "value": 20783,
            "unit": "ns/op",
            "extra": "57133 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - B/op",
            "value": 544,
            "unit": "B/op",
            "extra": "57133 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57133 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small",
            "value": 20257,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "57878 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - ns/op",
            "value": 20257,
            "unit": "ns/op",
            "extra": "57878 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "57878 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57878 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium",
            "value": 20284,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "57934 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - ns/op",
            "value": 20284,
            "unit": "ns/op",
            "extra": "57934 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "57934 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57934 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large",
            "value": 20931,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "58658 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - ns/op",
            "value": 20931,
            "unit": "ns/op",
            "extra": "58658 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "58658 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58658 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small",
            "value": 19832,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "60919 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - ns/op",
            "value": 19832,
            "unit": "ns/op",
            "extra": "60919 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "60919 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60919 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium",
            "value": 19628,
            "unit": "ns/op\t     534 B/op\t      57 allocs/op",
            "extra": "61045 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - ns/op",
            "value": 19628,
            "unit": "ns/op",
            "extra": "61045 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - B/op",
            "value": 534,
            "unit": "B/op",
            "extra": "61045 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "61045 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large",
            "value": 19585,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "58999 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - ns/op",
            "value": 19585,
            "unit": "ns/op",
            "extra": "58999 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "58999 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58999 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small",
            "value": 20110,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "54400 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - ns/op",
            "value": 20110,
            "unit": "ns/op",
            "extra": "54400 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "54400 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "54400 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium",
            "value": 20152,
            "unit": "ns/op\t     538 B/op\t      58 allocs/op",
            "extra": "57600 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - ns/op",
            "value": 20152,
            "unit": "ns/op",
            "extra": "57600 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - B/op",
            "value": 538,
            "unit": "B/op",
            "extra": "57600 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57600 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large",
            "value": 20379,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "58254 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - ns/op",
            "value": 20379,
            "unit": "ns/op",
            "extra": "58254 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "58254 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58254 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small",
            "value": 20337,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58012 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - ns/op",
            "value": 20337,
            "unit": "ns/op",
            "extra": "58012 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58012 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58012 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium",
            "value": 20092,
            "unit": "ns/op\t     544 B/op\t      58 allocs/op",
            "extra": "58125 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - ns/op",
            "value": 20092,
            "unit": "ns/op",
            "extra": "58125 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - B/op",
            "value": 544,
            "unit": "B/op",
            "extra": "58125 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58125 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large",
            "value": 20326,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "57969 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - ns/op",
            "value": 20326,
            "unit": "ns/op",
            "extra": "57969 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "57969 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57969 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration",
            "value": 5.63,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "212739318 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - ns/op",
            "value": 5.63,
            "unit": "ns/op",
            "extra": "212739318 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "212739318 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "212739318 times\n4 procs"
          },
          {
            "name": "BenchmarkInterpolation",
            "value": 1e-7,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkInterpolation - ns/op",
            "value": 1e-7,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkInterpolation - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkInterpolation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling",
            "value": 0.0000202,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling - ns/op",
            "value": 0.0000202,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2",
            "value": 39842,
            "unit": "ns/op\t    1359 B/op\t     114 allocs/op",
            "extra": "30189 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - ns/op",
            "value": 39842,
            "unit": "ns/op",
            "extra": "30189 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - B/op",
            "value": 1359,
            "unit": "B/op",
            "extra": "30189 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30189 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4",
            "value": 39771,
            "unit": "ns/op\t    1366 B/op\t     114 allocs/op",
            "extra": "30117 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - ns/op",
            "value": 39771,
            "unit": "ns/op",
            "extra": "30117 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - B/op",
            "value": 1366,
            "unit": "B/op",
            "extra": "30117 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30117 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8",
            "value": 39652,
            "unit": "ns/op\t    1361 B/op\t     114 allocs/op",
            "extra": "30210 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - ns/op",
            "value": 39652,
            "unit": "ns/op",
            "extra": "30210 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - B/op",
            "value": 1361,
            "unit": "B/op",
            "extra": "30210 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30210 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1m0s",
            "value": 5e-7,
            "unit": "ns/op\t        70.00 datapoints\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1m0s - ns/op",
            "value": 5e-7,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1m0s - datapoints",
            "value": 70,
            "unit": "datapoints",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1m0s - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1m0s - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1h0m0s",
            "value": 6e-7,
            "unit": "ns/op\t      3610 datapoints\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1h0m0s - ns/op",
            "value": 6e-7,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1h0m0s - datapoints",
            "value": 3610,
            "unit": "datapoints",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1h0m0s - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1h0m0s - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s",
            "value": 9e-7,
            "unit": "ns/op\t      3610 datapoints\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s - ns/op",
            "value": 9e-7,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s - datapoints",
            "value": 3610,
            "unit": "datapoints",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess",
            "value": 21557,
            "unit": "ns/op\t   53206 B/op\t      37 allocs/op",
            "extra": "56974 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - ns/op",
            "value": 21557,
            "unit": "ns/op",
            "extra": "56974 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - B/op",
            "value": 53206,
            "unit": "B/op",
            "extra": "56974 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "56974 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation",
            "value": 55.44,
            "unit": "ns/op\t        32.00 bytes/point\t       0 B/op\t       0 allocs/op",
            "extra": "21646555 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - ns/op",
            "value": 55.44,
            "unit": "ns/op",
            "extra": "21646555 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - bytes/point",
            "value": 32,
            "unit": "bytes/point",
            "extra": "21646555 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21646555 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21646555 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData",
            "value": 255964,
            "unit": "ns/op\t  123584 B/op\t      19 allocs/op",
            "extra": "4374 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - ns/op",
            "value": 255964,
            "unit": "ns/op",
            "extra": "4374 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - B/op",
            "value": 123584,
            "unit": "B/op",
            "extra": "4374 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - allocs/op",
            "value": 19,
            "unit": "allocs/op",
            "extra": "4374 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing",
            "value": 5616,
            "unit": "ns/op\t 213680000 packets/op\t       0 B/op\t       0 allocs/op",
            "extra": "213680 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - ns/op",
            "value": 5616,
            "unit": "ns/op",
            "extra": "213680 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - packets/op",
            "value": 213680000,
            "unit": "packets/op",
            "extra": "213680 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "213680 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "213680 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit",
            "value": 2.494,
            "unit": "ns/op\t       100.0 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "480594206 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - ns/op",
            "value": 2.494,
            "unit": "ns/op",
            "extra": "480594206 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allowed%",
            "value": 100,
            "unit": "allowed%",
            "extra": "480594206 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "480594206 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "480594206 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS",
            "value": 118.5,
            "unit": "ns/op\t         0.1283 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10168200 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - ns/op",
            "value": 118.5,
            "unit": "ns/op",
            "extra": "10168200 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allowed%",
            "value": 0.1283,
            "unit": "allowed%",
            "extra": "10168200 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10168200 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10168200 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS",
            "value": 118,
            "unit": "ns/op\t         1.278 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10157637 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - ns/op",
            "value": 118,
            "unit": "ns/op",
            "extra": "10157637 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allowed%",
            "value": 1.278,
            "unit": "allowed%",
            "extra": "10157637 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10157637 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10157637 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS",
            "value": 119.1,
            "unit": "ns/op\t        12.90 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10154448 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - ns/op",
            "value": 119.1,
            "unit": "ns/op",
            "extra": "10154448 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allowed%",
            "value": 12.9,
            "unit": "allowed%",
            "extra": "10154448 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10154448 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10154448 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool",
            "value": 326.7,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "3680522 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - ns/op",
            "value": 326.7,
            "unit": "ns/op",
            "extra": "3680522 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "3680522 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "3680522 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool",
            "value": 2402,
            "unit": "ns/op\t   14560 B/op\t       1 allocs/op",
            "extra": "487027 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - ns/op",
            "value": 2402,
            "unit": "ns/op",
            "extra": "487027 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - B/op",
            "value": 14560,
            "unit": "B/op",
            "extra": "487027 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "487027 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController",
            "value": 336.1,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3549506 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - ns/op",
            "value": 336.1,
            "unit": "ns/op",
            "extra": "3549506 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3549506 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3549506 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64",
            "value": 5.305,
            "unit": "ns/op\t12064.36 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226371646 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - ns/op",
            "value": 5.305,
            "unit": "ns/op",
            "extra": "226371646 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - MB/s",
            "value": 12064.36,
            "unit": "MB/s",
            "extra": "226371646 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226371646 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226371646 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256",
            "value": 5.298,
            "unit": "ns/op\t48319.71 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226567232 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - ns/op",
            "value": 5.298,
            "unit": "ns/op",
            "extra": "226567232 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - MB/s",
            "value": 48319.71,
            "unit": "MB/s",
            "extra": "226567232 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226567232 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226567232 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512",
            "value": 5.305,
            "unit": "ns/op\t96510.43 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226630335 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - ns/op",
            "value": 5.305,
            "unit": "ns/op",
            "extra": "226630335 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - MB/s",
            "value": 96510.43,
            "unit": "MB/s",
            "extra": "226630335 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226630335 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226630335 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024",
            "value": 5.293,
            "unit": "ns/op\t193460.45 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226324354 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - ns/op",
            "value": 5.293,
            "unit": "ns/op",
            "extra": "226324354 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - MB/s",
            "value": 193460.45,
            "unit": "MB/s",
            "extra": "226324354 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226324354 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226324354 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500",
            "value": 5.301,
            "unit": "ns/op\t282962.20 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "225775662 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - ns/op",
            "value": 5.301,
            "unit": "ns/op",
            "extra": "225775662 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - MB/s",
            "value": 282962.2,
            "unit": "MB/s",
            "extra": "225775662 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "225775662 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "225775662 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000",
            "value": 5.292,
            "unit": "ns/op\t1700696.02 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226431981 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - ns/op",
            "value": 5.292,
            "unit": "ns/op",
            "extra": "226431981 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - MB/s",
            "value": 1700696.02,
            "unit": "MB/s",
            "extra": "226431981 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226431981 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226431981 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline",
            "value": 54741,
            "unit": "ns/op\t         0 MB/op\t       0 B/op\t       0 allocs/op",
            "extra": "21912 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - ns/op",
            "value": 54741,
            "unit": "ns/op",
            "extra": "21912 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - MB/op",
            "value": 0,
            "unit": "MB/op",
            "extra": "21912 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21912 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21912 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple",
            "value": 90.28,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "13382611 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - ns/op",
            "value": 90.28,
            "unit": "ns/op",
            "extra": "13382611 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "13382611 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "13382611 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID",
            "value": 272.3,
            "unit": "ns/op\t      61 B/op\t       3 allocs/op",
            "extra": "4389813 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - ns/op",
            "value": 272.3,
            "unit": "ns/op",
            "extra": "4389813 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - B/op",
            "value": 61,
            "unit": "B/op",
            "extra": "4389813 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "4389813 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket",
            "value": 282.2,
            "unit": "ns/op\t    3342 B/op\t       0 allocs/op",
            "extra": "5070346 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - ns/op",
            "value": 282.2,
            "unit": "ns/op",
            "extra": "5070346 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - B/op",
            "value": 3342,
            "unit": "B/op",
            "extra": "5070346 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "5070346 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small",
            "value": 22182,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "53941 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - ns/op",
            "value": 22182,
            "unit": "ns/op",
            "extra": "53941 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "53941 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53941 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium",
            "value": 22111,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "53859 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - ns/op",
            "value": 22111,
            "unit": "ns/op",
            "extra": "53859 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "53859 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53859 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large",
            "value": 22169,
            "unit": "ns/op\t     723 B/op\t      59 allocs/op",
            "extra": "54090 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - ns/op",
            "value": 22169,
            "unit": "ns/op",
            "extra": "54090 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - B/op",
            "value": 723,
            "unit": "B/op",
            "extra": "54090 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54090 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small",
            "value": 20220,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58926 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - ns/op",
            "value": 20220,
            "unit": "ns/op",
            "extra": "58926 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58926 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58926 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium",
            "value": 20197,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "59030 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - ns/op",
            "value": 20197,
            "unit": "ns/op",
            "extra": "59030 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "59030 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59030 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large",
            "value": 20258,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58150 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - ns/op",
            "value": 20258,
            "unit": "ns/op",
            "extra": "58150 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58150 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58150 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small",
            "value": 20078,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "59106 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - ns/op",
            "value": 20078,
            "unit": "ns/op",
            "extra": "59106 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "59106 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59106 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium",
            "value": 20152,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "59316 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - ns/op",
            "value": 20152,
            "unit": "ns/op",
            "extra": "59316 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "59316 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59316 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large",
            "value": 20134,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "58743 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - ns/op",
            "value": 20134,
            "unit": "ns/op",
            "extra": "58743 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "58743 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58743 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix",
            "value": 42743,
            "unit": "ns/op\t   28683 B/op\t     345 allocs/op",
            "extra": "27991 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - ns/op",
            "value": 42743,
            "unit": "ns/op",
            "extra": "27991 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - B/op",
            "value": 28683,
            "unit": "B/op",
            "extra": "27991 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - allocs/op",
            "value": 345,
            "unit": "allocs/op",
            "extra": "27991 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap",
            "value": 6150,
            "unit": "ns/op\t    3568 B/op\t      49 allocs/op",
            "extra": "188544 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - ns/op",
            "value": 6150,
            "unit": "ns/op",
            "extra": "188544 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - B/op",
            "value": 3568,
            "unit": "B/op",
            "extra": "188544 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "188544 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer",
            "value": 9545,
            "unit": "ns/op\t    7257 B/op\t      34 allocs/op",
            "extra": "123862 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - ns/op",
            "value": 9545,
            "unit": "ns/op",
            "extra": "123862 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - B/op",
            "value": 7257,
            "unit": "B/op",
            "extra": "123862 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - allocs/op",
            "value": 34,
            "unit": "allocs/op",
            "extra": "123862 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey",
            "value": 2361,
            "unit": "ns/op\t    1400 B/op\t      27 allocs/op",
            "extra": "470794 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - ns/op",
            "value": 2361,
            "unit": "ns/op",
            "extra": "470794 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - B/op",
            "value": 1400,
            "unit": "B/op",
            "extra": "470794 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "470794 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial",
            "value": 16429,
            "unit": "ns/op\t   16466 B/op\t      98 allocs/op",
            "extra": "72079 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - ns/op",
            "value": 16429,
            "unit": "ns/op",
            "extra": "72079 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - B/op",
            "value": 16466,
            "unit": "B/op",
            "extra": "72079 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - allocs/op",
            "value": 98,
            "unit": "allocs/op",
            "extra": "72079 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor",
            "value": 8.726,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "137427818 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - ns/op",
            "value": 8.726,
            "unit": "ns/op",
            "extra": "137427818 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "137427818 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "137427818 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor",
            "value": 24.13,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "49721113 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - ns/op",
            "value": 24.13,
            "unit": "ns/op",
            "extra": "49721113 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "49721113 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "49721113 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex",
            "value": 36.21,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "32477893 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - ns/op",
            "value": 36.21,
            "unit": "ns/op",
            "extra": "32477893 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "32477893 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "32477893 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow",
            "value": 6.553,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "183490467 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - ns/op",
            "value": 6.553,
            "unit": "ns/op",
            "extra": "183490467 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "183490467 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "183490467 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse",
            "value": 18.61,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "64364263 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - ns/op",
            "value": 18.61,
            "unit": "ns/op",
            "extra": "64364263 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "64364263 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "64364263 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire",
            "value": 5.918,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "202474918 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - ns/op",
            "value": 5.918,
            "unit": "ns/op",
            "extra": "202474918 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "202474918 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "202474918 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix",
            "value": 3.749,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "320209706 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - ns/op",
            "value": 3.749,
            "unit": "ns/op",
            "extra": "320209706 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "320209706 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "320209706 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave",
            "value": 32.83,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "36542091 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - ns/op",
            "value": 32.83,
            "unit": "ns/op",
            "extra": "36542091 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "36542091 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "36542091 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle",
            "value": 3.743,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "320752838 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - ns/op",
            "value": 3.743,
            "unit": "ns/op",
            "extra": "320752838 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "320752838 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "320752838 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10",
            "value": 102793,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10 - ns/op",
            "value": 102793,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10 - B/op",
            "value": 5176,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10 - allocs/op",
            "value": 196,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100",
            "value": 102471,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - ns/op",
            "value": 102471,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - B/op",
            "value": 5176,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - allocs/op",
            "value": 196,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000",
            "value": 102542,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000 - ns/op",
            "value": 102542,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000 - B/op",
            "value": 5176,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000 - allocs/op",
            "value": 196,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate",
            "value": 439.2,
            "unit": "ns/op\t     229 B/op\t       3 allocs/op",
            "extra": "2724741 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - ns/op",
            "value": 439.2,
            "unit": "ns/op",
            "extra": "2724741 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - B/op",
            "value": 229,
            "unit": "B/op",
            "extra": "2724741 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2724741 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2",
            "value": 8893,
            "unit": "ns/op\t   17464 B/op\t      77 allocs/op",
            "extra": "130375 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - ns/op",
            "value": 8893,
            "unit": "ns/op",
            "extra": "130375 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - B/op",
            "value": 17464,
            "unit": "B/op",
            "extra": "130375 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - allocs/op",
            "value": 77,
            "unit": "allocs/op",
            "extra": "130375 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3",
            "value": 24560,
            "unit": "ns/op\t   47576 B/op\t     200 allocs/op",
            "extra": "48747 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - ns/op",
            "value": 24560,
            "unit": "ns/op",
            "extra": "48747 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - B/op",
            "value": 47576,
            "unit": "B/op",
            "extra": "48747 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - allocs/op",
            "value": 200,
            "unit": "allocs/op",
            "extra": "48747 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4",
            "value": 35029,
            "unit": "ns/op\t   69816 B/op\t     295 allocs/op",
            "extra": "34053 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - ns/op",
            "value": 35029,
            "unit": "ns/op",
            "extra": "34053 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - B/op",
            "value": 69816,
            "unit": "B/op",
            "extra": "34053 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - allocs/op",
            "value": 295,
            "unit": "allocs/op",
            "extra": "34053 times\n4 procs"
          }
        ]
      }
    ]
  }
}