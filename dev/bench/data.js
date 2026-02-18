window.BENCHMARK_DATA = {
  "lastUpdate": 1771421524198,
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
      },
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
          "id": "31e3e5cbc98325c2ecefbcd68d8b07469e1f7ecb",
          "message": "ci: fix Benchmark checkout and Docker arm64 build (#47)\n\n- Benchmark: save SHA before orphan checkout, restore with explicit ref\n  (git checkout - fails after --orphan since there's no previous branch)\n- Docker: build only linux/amd64 to avoid QEMU cross-compilation linker\n  failure; remove QEMU setup step since it's no longer needed",
          "timestamp": "2026-02-18T00:19:13-05:00",
          "tree_id": "8b310469f1c630b3549c82ff5ce4bf1cc7077f6b",
          "url": "https://github.com/perplext/nsd/commit/31e3e5cbc98325c2ecefbcd68d8b07469e1f7ecb"
        },
        "date": 1771392252847,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkProcessTLSPacket",
            "value": 606,
            "unit": "ns/op\t     208 B/op\t       8 allocs/op",
            "extra": "1933972 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - ns/op",
            "value": 606,
            "unit": "ns/op",
            "extra": "1933972 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - B/op",
            "value": 208,
            "unit": "B/op",
            "extra": "1933972 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1933972 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes",
            "value": 7063,
            "unit": "ns/op\t    1588 B/op\t      93 allocs/op",
            "extra": "148851 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - ns/op",
            "value": 7063,
            "unit": "ns/op",
            "extra": "148851 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - B/op",
            "value": 1588,
            "unit": "B/op",
            "extra": "148851 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - allocs/op",
            "value": 93,
            "unit": "allocs/op",
            "extra": "148851 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint",
            "value": 160.3,
            "unit": "ns/op\t      60 B/op\t       0 allocs/op",
            "extra": "7476526 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - ns/op",
            "value": 160.3,
            "unit": "ns/op",
            "extra": "7476526 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - B/op",
            "value": 60,
            "unit": "B/op",
            "extra": "7476526 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "7476526 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint",
            "value": 247.7,
            "unit": "ns/op\t     121 B/op\t       0 allocs/op",
            "extra": "4790950 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - ns/op",
            "value": 247.7,
            "unit": "ns/op",
            "extra": "4790950 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - B/op",
            "value": 121,
            "unit": "B/op",
            "extra": "4790950 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4790950 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc",
            "value": 252.6,
            "unit": "ns/op\t      16 B/op\t       2 allocs/op",
            "extra": "4746157 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - ns/op",
            "value": 252.6,
            "unit": "ns/op",
            "extra": "4746157 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - B/op",
            "value": 16,
            "unit": "B/op",
            "extra": "4746157 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - allocs/op",
            "value": 2,
            "unit": "allocs/op",
            "extra": "4746157 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint",
            "value": 1368,
            "unit": "ns/op\t      1000 datapoints\t     183 B/op\t       0 allocs/op",
            "extra": "870096 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - ns/op",
            "value": 1368,
            "unit": "ns/op",
            "extra": "870096 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - datapoints",
            "value": 1000,
            "unit": "datapoints",
            "extra": "870096 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - B/op",
            "value": 183,
            "unit": "B/op",
            "extra": "870096 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "870096 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation",
            "value": 219.9,
            "unit": "ns/op\t     126 B/op\t       0 allocs/op",
            "extra": "5408793 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - ns/op",
            "value": 219.9,
            "unit": "ns/op",
            "extra": "5408793 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - B/op",
            "value": 126,
            "unit": "B/op",
            "extra": "5408793 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "5408793 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData",
            "value": 240213,
            "unit": "ns/op\t  106801 B/op\t      13 allocs/op",
            "extra": "4690 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - ns/op",
            "value": 240213,
            "unit": "ns/op",
            "extra": "4690 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - B/op",
            "value": 106801,
            "unit": "B/op",
            "extra": "4690 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - allocs/op",
            "value": 13,
            "unit": "allocs/op",
            "extra": "4690 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small",
            "value": 22152,
            "unit": "ns/op\t     727 B/op\t      59 allocs/op",
            "extra": "53692 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - ns/op",
            "value": 22152,
            "unit": "ns/op",
            "extra": "53692 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - B/op",
            "value": 727,
            "unit": "B/op",
            "extra": "53692 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53692 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium",
            "value": 21897,
            "unit": "ns/op\t     727 B/op\t      59 allocs/op",
            "extra": "54771 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - ns/op",
            "value": 21897,
            "unit": "ns/op",
            "extra": "54771 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - B/op",
            "value": 727,
            "unit": "B/op",
            "extra": "54771 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54771 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large",
            "value": 22235,
            "unit": "ns/op\t     729 B/op\t      59 allocs/op",
            "extra": "54429 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - ns/op",
            "value": 22235,
            "unit": "ns/op",
            "extra": "54429 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - B/op",
            "value": 729,
            "unit": "B/op",
            "extra": "54429 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54429 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small",
            "value": 22059,
            "unit": "ns/op\t     701 B/op\t      60 allocs/op",
            "extra": "53264 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - ns/op",
            "value": 22059,
            "unit": "ns/op",
            "extra": "53264 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - B/op",
            "value": 701,
            "unit": "B/op",
            "extra": "53264 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53264 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium",
            "value": 22453,
            "unit": "ns/op\t     701 B/op\t      60 allocs/op",
            "extra": "52254 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - ns/op",
            "value": 22453,
            "unit": "ns/op",
            "extra": "52254 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - B/op",
            "value": 701,
            "unit": "B/op",
            "extra": "52254 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52254 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large",
            "value": 22678,
            "unit": "ns/op\t     704 B/op\t      60 allocs/op",
            "extra": "53176 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - ns/op",
            "value": 22678,
            "unit": "ns/op",
            "extra": "53176 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - B/op",
            "value": 704,
            "unit": "B/op",
            "extra": "53176 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53176 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small",
            "value": 22229,
            "unit": "ns/op\t     701 B/op\t      60 allocs/op",
            "extra": "53644 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - ns/op",
            "value": 22229,
            "unit": "ns/op",
            "extra": "53644 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - B/op",
            "value": 701,
            "unit": "B/op",
            "extra": "53644 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53644 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium",
            "value": 22456,
            "unit": "ns/op\t     701 B/op\t      60 allocs/op",
            "extra": "53522 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - ns/op",
            "value": 22456,
            "unit": "ns/op",
            "extra": "53522 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - B/op",
            "value": 701,
            "unit": "B/op",
            "extra": "53522 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53522 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large",
            "value": 22405,
            "unit": "ns/op\t     704 B/op\t      60 allocs/op",
            "extra": "52618 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - ns/op",
            "value": 22405,
            "unit": "ns/op",
            "extra": "52618 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - B/op",
            "value": 704,
            "unit": "B/op",
            "extra": "52618 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52618 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small",
            "value": 19896,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "58366 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - ns/op",
            "value": 19896,
            "unit": "ns/op",
            "extra": "58366 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "58366 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58366 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium",
            "value": 19829,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "59415 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - ns/op",
            "value": 19829,
            "unit": "ns/op",
            "extra": "59415 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "59415 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59415 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large",
            "value": 20495,
            "unit": "ns/op\t     535 B/op\t      57 allocs/op",
            "extra": "59578 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - ns/op",
            "value": 20495,
            "unit": "ns/op",
            "extra": "59578 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - B/op",
            "value": 535,
            "unit": "B/op",
            "extra": "59578 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59578 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small",
            "value": 20971,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58750 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - ns/op",
            "value": 20971,
            "unit": "ns/op",
            "extra": "58750 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58750 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58750 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium",
            "value": 20618,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "58639 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - ns/op",
            "value": 20618,
            "unit": "ns/op",
            "extra": "58639 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "58639 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58639 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large",
            "value": 20737,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "58291 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - ns/op",
            "value": 20737,
            "unit": "ns/op",
            "extra": "58291 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "58291 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58291 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small",
            "value": 20868,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "58509 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - ns/op",
            "value": 20868,
            "unit": "ns/op",
            "extra": "58509 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "58509 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58509 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium",
            "value": 20652,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58376 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - ns/op",
            "value": 20652,
            "unit": "ns/op",
            "extra": "58376 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58376 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58376 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large",
            "value": 20346,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "57693 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - ns/op",
            "value": 20346,
            "unit": "ns/op",
            "extra": "57693 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "57693 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57693 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small",
            "value": 19550,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "59700 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - ns/op",
            "value": 19550,
            "unit": "ns/op",
            "extra": "59700 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "59700 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59700 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium",
            "value": 19692,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "59300 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - ns/op",
            "value": 19692,
            "unit": "ns/op",
            "extra": "59300 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "59300 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59300 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large",
            "value": 19706,
            "unit": "ns/op\t     537 B/op\t      57 allocs/op",
            "extra": "58664 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - ns/op",
            "value": 19706,
            "unit": "ns/op",
            "extra": "58664 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - B/op",
            "value": 537,
            "unit": "B/op",
            "extra": "58664 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58664 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small",
            "value": 20423,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "57291 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - ns/op",
            "value": 20423,
            "unit": "ns/op",
            "extra": "57291 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "57291 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57291 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium",
            "value": 20556,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58322 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - ns/op",
            "value": 20556,
            "unit": "ns/op",
            "extra": "58322 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58322 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58322 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large",
            "value": 20389,
            "unit": "ns/op\t     545 B/op\t      58 allocs/op",
            "extra": "59058 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - ns/op",
            "value": 20389,
            "unit": "ns/op",
            "extra": "59058 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - B/op",
            "value": 545,
            "unit": "B/op",
            "extra": "59058 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "59058 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small",
            "value": 20138,
            "unit": "ns/op\t     538 B/op\t      58 allocs/op",
            "extra": "57609 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - ns/op",
            "value": 20138,
            "unit": "ns/op",
            "extra": "57609 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - B/op",
            "value": 538,
            "unit": "B/op",
            "extra": "57609 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57609 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium",
            "value": 20145,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "58230 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - ns/op",
            "value": 20145,
            "unit": "ns/op",
            "extra": "58230 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "58230 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58230 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large",
            "value": 20241,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "58084 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - ns/op",
            "value": 20241,
            "unit": "ns/op",
            "extra": "58084 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "58084 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58084 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration",
            "value": 5.65,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "212683800 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - ns/op",
            "value": 5.65,
            "unit": "ns/op",
            "extra": "212683800 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "212683800 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "212683800 times\n4 procs"
          },
          {
            "name": "BenchmarkInterpolation",
            "value": 4e-7,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkInterpolation - ns/op",
            "value": 4e-7,
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
            "value": 0.0000181,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling - ns/op",
            "value": 0.0000181,
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
            "value": 39919,
            "unit": "ns/op\t    1363 B/op\t     114 allocs/op",
            "extra": "30099 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - ns/op",
            "value": 39919,
            "unit": "ns/op",
            "extra": "30099 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - B/op",
            "value": 1363,
            "unit": "B/op",
            "extra": "30099 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30099 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4",
            "value": 39780,
            "unit": "ns/op\t    1363 B/op\t     114 allocs/op",
            "extra": "30026 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - ns/op",
            "value": 39780,
            "unit": "ns/op",
            "extra": "30026 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - B/op",
            "value": 1363,
            "unit": "B/op",
            "extra": "30026 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30026 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8",
            "value": 39768,
            "unit": "ns/op\t    1365 B/op\t     114 allocs/op",
            "extra": "30170 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - ns/op",
            "value": 39768,
            "unit": "ns/op",
            "extra": "30170 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - B/op",
            "value": 1365,
            "unit": "B/op",
            "extra": "30170 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30170 times\n4 procs"
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
            "value": 21787,
            "unit": "ns/op\t   53180 B/op\t      37 allocs/op",
            "extra": "57171 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - ns/op",
            "value": 21787,
            "unit": "ns/op",
            "extra": "57171 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - B/op",
            "value": 53180,
            "unit": "B/op",
            "extra": "57171 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "57171 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation",
            "value": 55.43,
            "unit": "ns/op\t        32.00 bytes/point\t       0 B/op\t       0 allocs/op",
            "extra": "21636291 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - ns/op",
            "value": 55.43,
            "unit": "ns/op",
            "extra": "21636291 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - bytes/point",
            "value": 32,
            "unit": "bytes/point",
            "extra": "21636291 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21636291 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21636291 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData",
            "value": 255455,
            "unit": "ns/op\t  123584 B/op\t      19 allocs/op",
            "extra": "4422 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - ns/op",
            "value": 255455,
            "unit": "ns/op",
            "extra": "4422 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - B/op",
            "value": 123584,
            "unit": "B/op",
            "extra": "4422 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - allocs/op",
            "value": 19,
            "unit": "allocs/op",
            "extra": "4422 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing",
            "value": 5620,
            "unit": "ns/op\t 213643000 packets/op\t       0 B/op\t       0 allocs/op",
            "extra": "213643 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - ns/op",
            "value": 5620,
            "unit": "ns/op",
            "extra": "213643 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - packets/op",
            "value": 213643000,
            "unit": "packets/op",
            "extra": "213643 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "213643 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "213643 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit",
            "value": 2.493,
            "unit": "ns/op\t       100.0 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "480855676 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - ns/op",
            "value": 2.493,
            "unit": "ns/op",
            "extra": "480855676 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allowed%",
            "value": 100,
            "unit": "allowed%",
            "extra": "480855676 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "480855676 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "480855676 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS",
            "value": 118.1,
            "unit": "ns/op\t         0.1279 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10161224 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - ns/op",
            "value": 118.1,
            "unit": "ns/op",
            "extra": "10161224 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allowed%",
            "value": 0.1279,
            "unit": "allowed%",
            "extra": "10161224 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10161224 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10161224 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS",
            "value": 118.3,
            "unit": "ns/op\t         1.281 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10148191 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - ns/op",
            "value": 118.3,
            "unit": "ns/op",
            "extra": "10148191 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allowed%",
            "value": 1.281,
            "unit": "allowed%",
            "extra": "10148191 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10148191 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10148191 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS",
            "value": 118.8,
            "unit": "ns/op\t        12.86 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10196269 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - ns/op",
            "value": 118.8,
            "unit": "ns/op",
            "extra": "10196269 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allowed%",
            "value": 12.86,
            "unit": "allowed%",
            "extra": "10196269 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10196269 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10196269 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool",
            "value": 324.6,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "3516422 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - ns/op",
            "value": 324.6,
            "unit": "ns/op",
            "extra": "3516422 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "3516422 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "3516422 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool",
            "value": 2446,
            "unit": "ns/op\t   14559 B/op\t       1 allocs/op",
            "extra": "484929 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - ns/op",
            "value": 2446,
            "unit": "ns/op",
            "extra": "484929 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - B/op",
            "value": 14559,
            "unit": "B/op",
            "extra": "484929 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "484929 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController",
            "value": 336.1,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3569672 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - ns/op",
            "value": 336.1,
            "unit": "ns/op",
            "extra": "3569672 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3569672 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3569672 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64",
            "value": 5.301,
            "unit": "ns/op\t12074.21 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226603894 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - ns/op",
            "value": 5.301,
            "unit": "ns/op",
            "extra": "226603894 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - MB/s",
            "value": 12074.21,
            "unit": "MB/s",
            "extra": "226603894 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226603894 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226603894 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256",
            "value": 5.297,
            "unit": "ns/op\t48325.00 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226563744 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - ns/op",
            "value": 5.297,
            "unit": "ns/op",
            "extra": "226563744 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - MB/s",
            "value": 48325,
            "unit": "MB/s",
            "extra": "226563744 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226563744 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226563744 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512",
            "value": 5.294,
            "unit": "ns/op\t96705.12 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226562455 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - ns/op",
            "value": 5.294,
            "unit": "ns/op",
            "extra": "226562455 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - MB/s",
            "value": 96705.12,
            "unit": "MB/s",
            "extra": "226562455 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226562455 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226562455 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024",
            "value": 5.297,
            "unit": "ns/op\t193305.35 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226401702 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - ns/op",
            "value": 5.297,
            "unit": "ns/op",
            "extra": "226401702 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - MB/s",
            "value": 193305.35,
            "unit": "MB/s",
            "extra": "226401702 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226401702 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226401702 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500",
            "value": 5.306,
            "unit": "ns/op\t282700.02 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226086570 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - ns/op",
            "value": 5.306,
            "unit": "ns/op",
            "extra": "226086570 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - MB/s",
            "value": 282700.02,
            "unit": "MB/s",
            "extra": "226086570 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226086570 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226086570 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000",
            "value": 5.366,
            "unit": "ns/op\t1677280.73 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226079319 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - ns/op",
            "value": 5.366,
            "unit": "ns/op",
            "extra": "226079319 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - MB/s",
            "value": 1677280.73,
            "unit": "MB/s",
            "extra": "226079319 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226079319 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226079319 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline",
            "value": 54675,
            "unit": "ns/op\t         0 MB/op\t       0 B/op\t       0 allocs/op",
            "extra": "21903 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - ns/op",
            "value": 54675,
            "unit": "ns/op",
            "extra": "21903 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - MB/op",
            "value": 0,
            "unit": "MB/op",
            "extra": "21903 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21903 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21903 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple",
            "value": 90.38,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "13167169 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - ns/op",
            "value": 90.38,
            "unit": "ns/op",
            "extra": "13167169 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "13167169 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "13167169 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID",
            "value": 272.2,
            "unit": "ns/op\t      61 B/op\t       3 allocs/op",
            "extra": "4343311 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - ns/op",
            "value": 272.2,
            "unit": "ns/op",
            "extra": "4343311 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - B/op",
            "value": 61,
            "unit": "B/op",
            "extra": "4343311 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "4343311 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket",
            "value": 261.7,
            "unit": "ns/op\t    3405 B/op\t       0 allocs/op",
            "extra": "4976028 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - ns/op",
            "value": 261.7,
            "unit": "ns/op",
            "extra": "4976028 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - B/op",
            "value": 3405,
            "unit": "B/op",
            "extra": "4976028 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4976028 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small",
            "value": 22292,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "54158 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - ns/op",
            "value": 22292,
            "unit": "ns/op",
            "extra": "54158 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "54158 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54158 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium",
            "value": 22346,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "53540 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - ns/op",
            "value": 22346,
            "unit": "ns/op",
            "extra": "53540 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "53540 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53540 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large",
            "value": 22219,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "53391 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - ns/op",
            "value": 22219,
            "unit": "ns/op",
            "extra": "53391 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "53391 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53391 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small",
            "value": 20195,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "58480 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - ns/op",
            "value": 20195,
            "unit": "ns/op",
            "extra": "58480 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "58480 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58480 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium",
            "value": 20167,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "58906 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - ns/op",
            "value": 20167,
            "unit": "ns/op",
            "extra": "58906 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "58906 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58906 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large",
            "value": 20269,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "58393 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - ns/op",
            "value": 20269,
            "unit": "ns/op",
            "extra": "58393 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "58393 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58393 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small",
            "value": 20143,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "59226 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - ns/op",
            "value": 20143,
            "unit": "ns/op",
            "extra": "59226 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "59226 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59226 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium",
            "value": 20051,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "55645 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - ns/op",
            "value": 20051,
            "unit": "ns/op",
            "extra": "55645 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "55645 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "55645 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large",
            "value": 20165,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "58617 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - ns/op",
            "value": 20165,
            "unit": "ns/op",
            "extra": "58617 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "58617 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58617 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix",
            "value": 42715,
            "unit": "ns/op\t   27267 B/op\t     340 allocs/op",
            "extra": "27999 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - ns/op",
            "value": 42715,
            "unit": "ns/op",
            "extra": "27999 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - B/op",
            "value": 27267,
            "unit": "B/op",
            "extra": "27999 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - allocs/op",
            "value": 340,
            "unit": "allocs/op",
            "extra": "27999 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap",
            "value": 6198,
            "unit": "ns/op\t    3568 B/op\t      49 allocs/op",
            "extra": "187519 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - ns/op",
            "value": 6198,
            "unit": "ns/op",
            "extra": "187519 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - B/op",
            "value": 3568,
            "unit": "B/op",
            "extra": "187519 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "187519 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer",
            "value": 9654,
            "unit": "ns/op\t    7257 B/op\t      34 allocs/op",
            "extra": "121519 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - ns/op",
            "value": 9654,
            "unit": "ns/op",
            "extra": "121519 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - B/op",
            "value": 7257,
            "unit": "B/op",
            "extra": "121519 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - allocs/op",
            "value": 34,
            "unit": "allocs/op",
            "extra": "121519 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey",
            "value": 2392,
            "unit": "ns/op\t    1400 B/op\t      27 allocs/op",
            "extra": "454654 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - ns/op",
            "value": 2392,
            "unit": "ns/op",
            "extra": "454654 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - B/op",
            "value": 1400,
            "unit": "B/op",
            "extra": "454654 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "454654 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial",
            "value": 16681,
            "unit": "ns/op\t   16466 B/op\t      98 allocs/op",
            "extra": "71175 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - ns/op",
            "value": 16681,
            "unit": "ns/op",
            "extra": "71175 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - B/op",
            "value": 16466,
            "unit": "B/op",
            "extra": "71175 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - allocs/op",
            "value": 98,
            "unit": "allocs/op",
            "extra": "71175 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor",
            "value": 8.744,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "137274506 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - ns/op",
            "value": 8.744,
            "unit": "ns/op",
            "extra": "137274506 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "137274506 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "137274506 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor",
            "value": 24.36,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "49478907 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - ns/op",
            "value": 24.36,
            "unit": "ns/op",
            "extra": "49478907 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "49478907 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "49478907 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex",
            "value": 36.26,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "33138748 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - ns/op",
            "value": 36.26,
            "unit": "ns/op",
            "extra": "33138748 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "33138748 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "33138748 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow",
            "value": 6.549,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "183461365 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - ns/op",
            "value": 6.549,
            "unit": "ns/op",
            "extra": "183461365 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "183461365 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "183461365 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse",
            "value": 18.51,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "64796320 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - ns/op",
            "value": 18.51,
            "unit": "ns/op",
            "extra": "64796320 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "64796320 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "64796320 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire",
            "value": 5.923,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "202772419 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - ns/op",
            "value": 5.923,
            "unit": "ns/op",
            "extra": "202772419 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "202772419 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "202772419 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix",
            "value": 3.744,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "320633823 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - ns/op",
            "value": 3.744,
            "unit": "ns/op",
            "extra": "320633823 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "320633823 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "320633823 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave",
            "value": 32.23,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "36797884 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - ns/op",
            "value": 32.23,
            "unit": "ns/op",
            "extra": "36797884 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "36797884 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "36797884 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle",
            "value": 3.741,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "319940005 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - ns/op",
            "value": 3.741,
            "unit": "ns/op",
            "extra": "319940005 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "319940005 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "319940005 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10",
            "value": 103399,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10 - ns/op",
            "value": 103399,
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
            "value": 102987,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "11560 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - ns/op",
            "value": 102987,
            "unit": "ns/op",
            "extra": "11560 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - B/op",
            "value": 5176,
            "unit": "B/op",
            "extra": "11560 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - allocs/op",
            "value": 196,
            "unit": "allocs/op",
            "extra": "11560 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000",
            "value": 102948,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000 - ns/op",
            "value": 102948,
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
            "value": 444.8,
            "unit": "ns/op\t     229 B/op\t       3 allocs/op",
            "extra": "2692136 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - ns/op",
            "value": 444.8,
            "unit": "ns/op",
            "extra": "2692136 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - B/op",
            "value": 229,
            "unit": "B/op",
            "extra": "2692136 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2692136 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2",
            "value": 9205,
            "unit": "ns/op\t   17464 B/op\t      77 allocs/op",
            "extra": "125355 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - ns/op",
            "value": 9205,
            "unit": "ns/op",
            "extra": "125355 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - B/op",
            "value": 17464,
            "unit": "B/op",
            "extra": "125355 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - allocs/op",
            "value": 77,
            "unit": "allocs/op",
            "extra": "125355 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3",
            "value": 25273,
            "unit": "ns/op\t   47576 B/op\t     200 allocs/op",
            "extra": "47293 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - ns/op",
            "value": 25273,
            "unit": "ns/op",
            "extra": "47293 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - B/op",
            "value": 47576,
            "unit": "B/op",
            "extra": "47293 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - allocs/op",
            "value": 200,
            "unit": "allocs/op",
            "extra": "47293 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4",
            "value": 36439,
            "unit": "ns/op\t   69816 B/op\t     295 allocs/op",
            "extra": "32625 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - ns/op",
            "value": 36439,
            "unit": "ns/op",
            "extra": "32625 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - B/op",
            "value": 69816,
            "unit": "B/op",
            "extra": "32625 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - allocs/op",
            "value": 295,
            "unit": "allocs/op",
            "extra": "32625 times\n4 procs"
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
          "id": "a6f13c47e54e297f4c7d4efce80a23639382371c",
          "message": "ci: remove broken release.yml workflow",
          "timestamp": "2026-02-18T05:19:18Z",
          "url": "https://github.com/perplext/nsd/pull/48/commits/a6f13c47e54e297f4c7d4efce80a23639382371c"
        },
        "date": 1771393367234,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkProcessTLSPacket",
            "value": 602.3,
            "unit": "ns/op\t     208 B/op\t       8 allocs/op",
            "extra": "1935498 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - ns/op",
            "value": 602.3,
            "unit": "ns/op",
            "extra": "1935498 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - B/op",
            "value": 208,
            "unit": "B/op",
            "extra": "1935498 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1935498 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes",
            "value": 7025,
            "unit": "ns/op\t    1588 B/op\t      93 allocs/op",
            "extra": "167131 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - ns/op",
            "value": 7025,
            "unit": "ns/op",
            "extra": "167131 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - B/op",
            "value": 1588,
            "unit": "B/op",
            "extra": "167131 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - allocs/op",
            "value": 93,
            "unit": "allocs/op",
            "extra": "167131 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint",
            "value": 162.4,
            "unit": "ns/op\t      60 B/op\t       0 allocs/op",
            "extra": "7527224 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - ns/op",
            "value": 162.4,
            "unit": "ns/op",
            "extra": "7527224 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - B/op",
            "value": 60,
            "unit": "B/op",
            "extra": "7527224 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "7527224 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint",
            "value": 247.7,
            "unit": "ns/op\t     121 B/op\t       0 allocs/op",
            "extra": "4781758 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - ns/op",
            "value": 247.7,
            "unit": "ns/op",
            "extra": "4781758 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - B/op",
            "value": 121,
            "unit": "B/op",
            "extra": "4781758 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4781758 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc",
            "value": 252.4,
            "unit": "ns/op\t      16 B/op\t       2 allocs/op",
            "extra": "4751455 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - ns/op",
            "value": 252.4,
            "unit": "ns/op",
            "extra": "4751455 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - B/op",
            "value": 16,
            "unit": "B/op",
            "extra": "4751455 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - allocs/op",
            "value": 2,
            "unit": "allocs/op",
            "extra": "4751455 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint",
            "value": 1369,
            "unit": "ns/op\t      1000 datapoints\t     183 B/op\t       0 allocs/op",
            "extra": "878559 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - ns/op",
            "value": 1369,
            "unit": "ns/op",
            "extra": "878559 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - datapoints",
            "value": 1000,
            "unit": "datapoints",
            "extra": "878559 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - B/op",
            "value": 183,
            "unit": "B/op",
            "extra": "878559 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "878559 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation",
            "value": 221.2,
            "unit": "ns/op\t     126 B/op\t       0 allocs/op",
            "extra": "5440642 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - ns/op",
            "value": 221.2,
            "unit": "ns/op",
            "extra": "5440642 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - B/op",
            "value": 126,
            "unit": "B/op",
            "extra": "5440642 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "5440642 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData",
            "value": 245340,
            "unit": "ns/op\t  106800 B/op\t      13 allocs/op",
            "extra": "4658 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - ns/op",
            "value": 245340,
            "unit": "ns/op",
            "extra": "4658 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - B/op",
            "value": 106800,
            "unit": "B/op",
            "extra": "4658 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - allocs/op",
            "value": 13,
            "unit": "allocs/op",
            "extra": "4658 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small",
            "value": 22471,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "54627 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - ns/op",
            "value": 22471,
            "unit": "ns/op",
            "extra": "54627 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "54627 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54627 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium",
            "value": 21868,
            "unit": "ns/op\t     727 B/op\t      59 allocs/op",
            "extra": "54438 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - ns/op",
            "value": 21868,
            "unit": "ns/op",
            "extra": "54438 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - B/op",
            "value": 727,
            "unit": "B/op",
            "extra": "54438 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54438 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large",
            "value": 22182,
            "unit": "ns/op\t     727 B/op\t      59 allocs/op",
            "extra": "49886 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - ns/op",
            "value": 22182,
            "unit": "ns/op",
            "extra": "49886 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - B/op",
            "value": 727,
            "unit": "B/op",
            "extra": "49886 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "49886 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small",
            "value": 22111,
            "unit": "ns/op\t     703 B/op\t      60 allocs/op",
            "extra": "54012 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - ns/op",
            "value": 22111,
            "unit": "ns/op",
            "extra": "54012 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - B/op",
            "value": 703,
            "unit": "B/op",
            "extra": "54012 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "54012 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium",
            "value": 22082,
            "unit": "ns/op\t     701 B/op\t      60 allocs/op",
            "extra": "53286 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - ns/op",
            "value": 22082,
            "unit": "ns/op",
            "extra": "53286 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - B/op",
            "value": 701,
            "unit": "B/op",
            "extra": "53286 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53286 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large",
            "value": 22268,
            "unit": "ns/op\t     704 B/op\t      60 allocs/op",
            "extra": "53782 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - ns/op",
            "value": 22268,
            "unit": "ns/op",
            "extra": "53782 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - B/op",
            "value": 704,
            "unit": "B/op",
            "extra": "53782 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53782 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small",
            "value": 22134,
            "unit": "ns/op\t     699 B/op\t      60 allocs/op",
            "extra": "52791 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - ns/op",
            "value": 22134,
            "unit": "ns/op",
            "extra": "52791 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - B/op",
            "value": 699,
            "unit": "B/op",
            "extra": "52791 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52791 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium",
            "value": 22099,
            "unit": "ns/op\t     703 B/op\t      60 allocs/op",
            "extra": "53660 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - ns/op",
            "value": 22099,
            "unit": "ns/op",
            "extra": "53660 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - B/op",
            "value": 703,
            "unit": "B/op",
            "extra": "53660 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53660 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large",
            "value": 22253,
            "unit": "ns/op\t     705 B/op\t      60 allocs/op",
            "extra": "53125 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - ns/op",
            "value": 22253,
            "unit": "ns/op",
            "extra": "53125 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - B/op",
            "value": 705,
            "unit": "B/op",
            "extra": "53125 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53125 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small",
            "value": 20196,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "59851 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - ns/op",
            "value": 20196,
            "unit": "ns/op",
            "extra": "59851 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "59851 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59851 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium",
            "value": 20112,
            "unit": "ns/op\t     535 B/op\t      57 allocs/op",
            "extra": "60146 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - ns/op",
            "value": 20112,
            "unit": "ns/op",
            "extra": "60146 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - B/op",
            "value": 535,
            "unit": "B/op",
            "extra": "60146 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60146 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large",
            "value": 19995,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "59340 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - ns/op",
            "value": 19995,
            "unit": "ns/op",
            "extra": "59340 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "59340 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59340 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small",
            "value": 20325,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "58482 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - ns/op",
            "value": 20325,
            "unit": "ns/op",
            "extra": "58482 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "58482 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58482 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium",
            "value": 20468,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "58611 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - ns/op",
            "value": 20468,
            "unit": "ns/op",
            "extra": "58611 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "58611 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58611 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large",
            "value": 20508,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "57764 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - ns/op",
            "value": 20508,
            "unit": "ns/op",
            "extra": "57764 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "57764 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57764 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small",
            "value": 20380,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "58644 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - ns/op",
            "value": 20380,
            "unit": "ns/op",
            "extra": "58644 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "58644 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58644 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium",
            "value": 20369,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58785 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - ns/op",
            "value": 20369,
            "unit": "ns/op",
            "extra": "58785 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58785 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58785 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large",
            "value": 20499,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "58149 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - ns/op",
            "value": 20499,
            "unit": "ns/op",
            "extra": "58149 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "58149 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58149 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small",
            "value": 19660,
            "unit": "ns/op\t     534 B/op\t      57 allocs/op",
            "extra": "60650 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - ns/op",
            "value": 19660,
            "unit": "ns/op",
            "extra": "60650 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - B/op",
            "value": 534,
            "unit": "B/op",
            "extra": "60650 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60650 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium",
            "value": 19658,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "60813 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - ns/op",
            "value": 19658,
            "unit": "ns/op",
            "extra": "60813 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "60813 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60813 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large",
            "value": 19796,
            "unit": "ns/op\t     535 B/op\t      57 allocs/op",
            "extra": "59704 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - ns/op",
            "value": 19796,
            "unit": "ns/op",
            "extra": "59704 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - B/op",
            "value": 535,
            "unit": "B/op",
            "extra": "59704 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59704 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small",
            "value": 20222,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "58726 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - ns/op",
            "value": 20222,
            "unit": "ns/op",
            "extra": "58726 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "58726 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58726 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium",
            "value": 20285,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58954 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - ns/op",
            "value": 20285,
            "unit": "ns/op",
            "extra": "58954 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58954 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58954 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large",
            "value": 20400,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58819 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - ns/op",
            "value": 20400,
            "unit": "ns/op",
            "extra": "58819 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58819 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58819 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small",
            "value": 20224,
            "unit": "ns/op\t     539 B/op\t      58 allocs/op",
            "extra": "58768 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - ns/op",
            "value": 20224,
            "unit": "ns/op",
            "extra": "58768 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - B/op",
            "value": 539,
            "unit": "B/op",
            "extra": "58768 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58768 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium",
            "value": 20315,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "59019 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - ns/op",
            "value": 20315,
            "unit": "ns/op",
            "extra": "59019 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "59019 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "59019 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large",
            "value": 20433,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "58432 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - ns/op",
            "value": 20433,
            "unit": "ns/op",
            "extra": "58432 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "58432 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58432 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration",
            "value": 5.665,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "212931096 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - ns/op",
            "value": 5.665,
            "unit": "ns/op",
            "extra": "212931096 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "212931096 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "212931096 times\n4 procs"
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
            "value": 0.0000109,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling - ns/op",
            "value": 0.0000109,
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
            "value": 40016,
            "unit": "ns/op\t    1358 B/op\t     114 allocs/op",
            "extra": "29972 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - ns/op",
            "value": 40016,
            "unit": "ns/op",
            "extra": "29972 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - B/op",
            "value": 1358,
            "unit": "B/op",
            "extra": "29972 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "29972 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4",
            "value": 40321,
            "unit": "ns/op\t    1355 B/op\t     114 allocs/op",
            "extra": "30032 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - ns/op",
            "value": 40321,
            "unit": "ns/op",
            "extra": "30032 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - B/op",
            "value": 1355,
            "unit": "B/op",
            "extra": "30032 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30032 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8",
            "value": 39923,
            "unit": "ns/op\t    1364 B/op\t     114 allocs/op",
            "extra": "29944 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - ns/op",
            "value": 39923,
            "unit": "ns/op",
            "extra": "29944 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - B/op",
            "value": 1364,
            "unit": "B/op",
            "extra": "29944 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "29944 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1m0s",
            "value": 8e-7,
            "unit": "ns/op\t        70.00 datapoints\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1m0s - ns/op",
            "value": 8e-7,
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
            "value": 4e-7,
            "unit": "ns/op\t      3610 datapoints\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/1h0m0s - ns/op",
            "value": 4e-7,
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
            "value": 21869,
            "unit": "ns/op\t   53136 B/op\t      37 allocs/op",
            "extra": "55058 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - ns/op",
            "value": 21869,
            "unit": "ns/op",
            "extra": "55058 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - B/op",
            "value": 53136,
            "unit": "B/op",
            "extra": "55058 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "55058 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation",
            "value": 55.41,
            "unit": "ns/op\t        32.00 bytes/point\t       0 B/op\t       0 allocs/op",
            "extra": "21661888 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - ns/op",
            "value": 55.41,
            "unit": "ns/op",
            "extra": "21661888 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - bytes/point",
            "value": 32,
            "unit": "bytes/point",
            "extra": "21661888 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21661888 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21661888 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData",
            "value": 256756,
            "unit": "ns/op\t  123584 B/op\t      19 allocs/op",
            "extra": "4309 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - ns/op",
            "value": 256756,
            "unit": "ns/op",
            "extra": "4309 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - B/op",
            "value": 123584,
            "unit": "B/op",
            "extra": "4309 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - allocs/op",
            "value": 19,
            "unit": "allocs/op",
            "extra": "4309 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing",
            "value": 5620,
            "unit": "ns/op\t 213871000 packets/op\t       0 B/op\t       0 allocs/op",
            "extra": "213871 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - ns/op",
            "value": 5620,
            "unit": "ns/op",
            "extra": "213871 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - packets/op",
            "value": 213871000,
            "unit": "packets/op",
            "extra": "213871 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "213871 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "213871 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit",
            "value": 2.49,
            "unit": "ns/op\t       100.0 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "481154774 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - ns/op",
            "value": 2.49,
            "unit": "ns/op",
            "extra": "481154774 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allowed%",
            "value": 100,
            "unit": "allowed%",
            "extra": "481154774 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "481154774 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "481154774 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS",
            "value": 118,
            "unit": "ns/op\t         0.1279 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10159807 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - ns/op",
            "value": 118,
            "unit": "ns/op",
            "extra": "10159807 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allowed%",
            "value": 0.1279,
            "unit": "allowed%",
            "extra": "10159807 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10159807 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10159807 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS",
            "value": 117.9,
            "unit": "ns/op\t         1.278 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10111988 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - ns/op",
            "value": 117.9,
            "unit": "ns/op",
            "extra": "10111988 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allowed%",
            "value": 1.278,
            "unit": "allowed%",
            "extra": "10111988 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10111988 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10111988 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS",
            "value": 118.7,
            "unit": "ns/op\t        12.85 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10187770 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - ns/op",
            "value": 118.7,
            "unit": "ns/op",
            "extra": "10187770 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allowed%",
            "value": 12.85,
            "unit": "allowed%",
            "extra": "10187770 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10187770 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10187770 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool",
            "value": 324.6,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "3698685 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - ns/op",
            "value": 324.6,
            "unit": "ns/op",
            "extra": "3698685 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "3698685 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "3698685 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool",
            "value": 2482,
            "unit": "ns/op\t   14560 B/op\t       1 allocs/op",
            "extra": "429073 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - ns/op",
            "value": 2482,
            "unit": "ns/op",
            "extra": "429073 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - B/op",
            "value": 14560,
            "unit": "B/op",
            "extra": "429073 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "429073 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController",
            "value": 336.7,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3564505 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - ns/op",
            "value": 336.7,
            "unit": "ns/op",
            "extra": "3564505 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3564505 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3564505 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64",
            "value": 5.297,
            "unit": "ns/op\t12082.53 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226358730 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - ns/op",
            "value": 5.297,
            "unit": "ns/op",
            "extra": "226358730 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - MB/s",
            "value": 12082.53,
            "unit": "MB/s",
            "extra": "226358730 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226358730 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226358730 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256",
            "value": 5.299,
            "unit": "ns/op\t48310.72 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226417014 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - ns/op",
            "value": 5.299,
            "unit": "ns/op",
            "extra": "226417014 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - MB/s",
            "value": 48310.72,
            "unit": "MB/s",
            "extra": "226417014 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226417014 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226417014 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512",
            "value": 5.294,
            "unit": "ns/op\t96707.09 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226452496 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - ns/op",
            "value": 5.294,
            "unit": "ns/op",
            "extra": "226452496 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - MB/s",
            "value": 96707.09,
            "unit": "MB/s",
            "extra": "226452496 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226452496 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226452496 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024",
            "value": 5.36,
            "unit": "ns/op\t191027.80 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226236705 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - ns/op",
            "value": 5.36,
            "unit": "ns/op",
            "extra": "226236705 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - MB/s",
            "value": 191027.8,
            "unit": "MB/s",
            "extra": "226236705 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226236705 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226236705 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500",
            "value": 5.3,
            "unit": "ns/op\t283013.18 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226208112 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - ns/op",
            "value": 5.3,
            "unit": "ns/op",
            "extra": "226208112 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - MB/s",
            "value": 283013.18,
            "unit": "MB/s",
            "extra": "226208112 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226208112 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226208112 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000",
            "value": 5.304,
            "unit": "ns/op\t1696680.65 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226642221 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - ns/op",
            "value": 5.304,
            "unit": "ns/op",
            "extra": "226642221 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - MB/s",
            "value": 1696680.65,
            "unit": "MB/s",
            "extra": "226642221 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226642221 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226642221 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline",
            "value": 55530,
            "unit": "ns/op\t         0 MB/op\t       0 B/op\t       0 allocs/op",
            "extra": "21738 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - ns/op",
            "value": 55530,
            "unit": "ns/op",
            "extra": "21738 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - MB/op",
            "value": 0,
            "unit": "MB/op",
            "extra": "21738 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21738 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21738 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple",
            "value": 90.48,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "13355352 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - ns/op",
            "value": 90.48,
            "unit": "ns/op",
            "extra": "13355352 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "13355352 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "13355352 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID",
            "value": 274.4,
            "unit": "ns/op\t      61 B/op\t       3 allocs/op",
            "extra": "4375675 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - ns/op",
            "value": 274.4,
            "unit": "ns/op",
            "extra": "4375675 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - B/op",
            "value": 61,
            "unit": "B/op",
            "extra": "4375675 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "4375675 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket",
            "value": 291.3,
            "unit": "ns/op\t    3443 B/op\t       0 allocs/op",
            "extra": "4920704 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - ns/op",
            "value": 291.3,
            "unit": "ns/op",
            "extra": "4920704 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - B/op",
            "value": 3443,
            "unit": "B/op",
            "extra": "4920704 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4920704 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small",
            "value": 22215,
            "unit": "ns/op\t     724 B/op\t      59 allocs/op",
            "extra": "54091 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - ns/op",
            "value": 22215,
            "unit": "ns/op",
            "extra": "54091 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - B/op",
            "value": 724,
            "unit": "B/op",
            "extra": "54091 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54091 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium",
            "value": 22172,
            "unit": "ns/op\t     724 B/op\t      59 allocs/op",
            "extra": "53770 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - ns/op",
            "value": 22172,
            "unit": "ns/op",
            "extra": "53770 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - B/op",
            "value": 724,
            "unit": "B/op",
            "extra": "53770 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53770 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large",
            "value": 22289,
            "unit": "ns/op\t     722 B/op\t      59 allocs/op",
            "extra": "53830 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - ns/op",
            "value": 22289,
            "unit": "ns/op",
            "extra": "53830 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - B/op",
            "value": 722,
            "unit": "B/op",
            "extra": "53830 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53830 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small",
            "value": 20356,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58051 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - ns/op",
            "value": 20356,
            "unit": "ns/op",
            "extra": "58051 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58051 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58051 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium",
            "value": 20245,
            "unit": "ns/op\t     529 B/op\t      57 allocs/op",
            "extra": "58827 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - ns/op",
            "value": 20245,
            "unit": "ns/op",
            "extra": "58827 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - B/op",
            "value": 529,
            "unit": "B/op",
            "extra": "58827 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58827 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large",
            "value": 20338,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "54429 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - ns/op",
            "value": 20338,
            "unit": "ns/op",
            "extra": "54429 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "54429 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "54429 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small",
            "value": 20269,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58562 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - ns/op",
            "value": 20269,
            "unit": "ns/op",
            "extra": "58562 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58562 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58562 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium",
            "value": 20068,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "59193 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - ns/op",
            "value": 20068,
            "unit": "ns/op",
            "extra": "59193 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "59193 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59193 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large",
            "value": 20296,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "58520 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - ns/op",
            "value": 20296,
            "unit": "ns/op",
            "extra": "58520 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "58520 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58520 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix",
            "value": 44344,
            "unit": "ns/op\t   27587 B/op\t     360 allocs/op",
            "extra": "26781 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - ns/op",
            "value": 44344,
            "unit": "ns/op",
            "extra": "26781 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - B/op",
            "value": 27587,
            "unit": "B/op",
            "extra": "26781 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - allocs/op",
            "value": 360,
            "unit": "allocs/op",
            "extra": "26781 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap",
            "value": 6124,
            "unit": "ns/op\t    3568 B/op\t      49 allocs/op",
            "extra": "188292 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - ns/op",
            "value": 6124,
            "unit": "ns/op",
            "extra": "188292 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - B/op",
            "value": 3568,
            "unit": "B/op",
            "extra": "188292 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "188292 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer",
            "value": 9550,
            "unit": "ns/op\t    7257 B/op\t      34 allocs/op",
            "extra": "122463 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - ns/op",
            "value": 9550,
            "unit": "ns/op",
            "extra": "122463 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - B/op",
            "value": 7257,
            "unit": "B/op",
            "extra": "122463 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - allocs/op",
            "value": 34,
            "unit": "allocs/op",
            "extra": "122463 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey",
            "value": 2357,
            "unit": "ns/op\t    1400 B/op\t      27 allocs/op",
            "extra": "467289 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - ns/op",
            "value": 2357,
            "unit": "ns/op",
            "extra": "467289 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - B/op",
            "value": 1400,
            "unit": "B/op",
            "extra": "467289 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "467289 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial",
            "value": 16516,
            "unit": "ns/op\t   16466 B/op\t      98 allocs/op",
            "extra": "71894 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - ns/op",
            "value": 16516,
            "unit": "ns/op",
            "extra": "71894 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - B/op",
            "value": 16466,
            "unit": "B/op",
            "extra": "71894 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - allocs/op",
            "value": 98,
            "unit": "allocs/op",
            "extra": "71894 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor",
            "value": 8.727,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "137137057 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - ns/op",
            "value": 8.727,
            "unit": "ns/op",
            "extra": "137137057 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "137137057 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "137137057 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor",
            "value": 24.16,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "48297096 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - ns/op",
            "value": 24.16,
            "unit": "ns/op",
            "extra": "48297096 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "48297096 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "48297096 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex",
            "value": 36.48,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "33155389 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - ns/op",
            "value": 36.48,
            "unit": "ns/op",
            "extra": "33155389 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "33155389 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "33155389 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow",
            "value": 6.535,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "183580324 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - ns/op",
            "value": 6.535,
            "unit": "ns/op",
            "extra": "183580324 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "183580324 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "183580324 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse",
            "value": 18.6,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "64505041 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - ns/op",
            "value": 18.6,
            "unit": "ns/op",
            "extra": "64505041 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "64505041 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "64505041 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire",
            "value": 5.918,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "202932122 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - ns/op",
            "value": 5.918,
            "unit": "ns/op",
            "extra": "202932122 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "202932122 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "202932122 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix",
            "value": 3.746,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "320751373 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - ns/op",
            "value": 3.746,
            "unit": "ns/op",
            "extra": "320751373 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "320751373 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "320751373 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave",
            "value": 32.65,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "36865429 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - ns/op",
            "value": 32.65,
            "unit": "ns/op",
            "extra": "36865429 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "36865429 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "36865429 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle",
            "value": 3.74,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "320600269 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - ns/op",
            "value": 3.74,
            "unit": "ns/op",
            "extra": "320600269 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "320600269 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "320600269 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10",
            "value": 103592,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10 - ns/op",
            "value": 103592,
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
            "value": 103808,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - ns/op",
            "value": 103808,
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
            "value": 103283,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000 - ns/op",
            "value": 103283,
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
            "value": 441.7,
            "unit": "ns/op\t     229 B/op\t       3 allocs/op",
            "extra": "2702613 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - ns/op",
            "value": 441.7,
            "unit": "ns/op",
            "extra": "2702613 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - B/op",
            "value": 229,
            "unit": "B/op",
            "extra": "2702613 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2702613 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2",
            "value": 8948,
            "unit": "ns/op\t   17464 B/op\t      77 allocs/op",
            "extra": "129873 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - ns/op",
            "value": 8948,
            "unit": "ns/op",
            "extra": "129873 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - B/op",
            "value": 17464,
            "unit": "B/op",
            "extra": "129873 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - allocs/op",
            "value": 77,
            "unit": "allocs/op",
            "extra": "129873 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3",
            "value": 24441,
            "unit": "ns/op\t   47576 B/op\t     200 allocs/op",
            "extra": "49317 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - ns/op",
            "value": 24441,
            "unit": "ns/op",
            "extra": "49317 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - B/op",
            "value": 47576,
            "unit": "B/op",
            "extra": "49317 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - allocs/op",
            "value": 200,
            "unit": "allocs/op",
            "extra": "49317 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4",
            "value": 35268,
            "unit": "ns/op\t   69816 B/op\t     295 allocs/op",
            "extra": "34071 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - ns/op",
            "value": 35268,
            "unit": "ns/op",
            "extra": "34071 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - B/op",
            "value": 69816,
            "unit": "B/op",
            "extra": "34071 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - allocs/op",
            "value": 295,
            "unit": "allocs/op",
            "extra": "34071 times\n4 procs"
          }
        ]
      },
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
          "id": "afa68d99b8324cf425f42d24e9e7b3b66e4a111c",
          "message": "ci: remove broken release.yml workflow (#48)\n\nThis workflow was firing on every push (despite tags-only filter),\nfailing with 0 jobs each time due to deprecated actions\n(actions/create-release@v1, actions/upload-release-asset@v1).\n\nFour functional release workflows already exist:\n- release-simple.yml\n- release-native.yml\n- release-all-platforms.yml\n- release-universal-simple.yml",
          "timestamp": "2026-02-18T07:42:07-05:00",
          "tree_id": "d5ede5cdbad414ecbfa80dafb47fd70269ddceb6",
          "url": "https://github.com/perplext/nsd/commit/afa68d99b8324cf425f42d24e9e7b3b66e4a111c"
        },
        "date": 1771418774849,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkProcessTLSPacket",
            "value": 594.8,
            "unit": "ns/op\t     208 B/op\t       8 allocs/op",
            "extra": "1995901 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - ns/op",
            "value": 594.8,
            "unit": "ns/op",
            "extra": "1995901 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - B/op",
            "value": 208,
            "unit": "B/op",
            "extra": "1995901 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1995901 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes",
            "value": 7244,
            "unit": "ns/op\t    1588 B/op\t      93 allocs/op",
            "extra": "166928 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - ns/op",
            "value": 7244,
            "unit": "ns/op",
            "extra": "166928 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - B/op",
            "value": 1588,
            "unit": "B/op",
            "extra": "166928 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - allocs/op",
            "value": 93,
            "unit": "allocs/op",
            "extra": "166928 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint",
            "value": 159.8,
            "unit": "ns/op\t      60 B/op\t       0 allocs/op",
            "extra": "7525922 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - ns/op",
            "value": 159.8,
            "unit": "ns/op",
            "extra": "7525922 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - B/op",
            "value": 60,
            "unit": "B/op",
            "extra": "7525922 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "7525922 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint",
            "value": 247.3,
            "unit": "ns/op\t     121 B/op\t       0 allocs/op",
            "extra": "4849306 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - ns/op",
            "value": 247.3,
            "unit": "ns/op",
            "extra": "4849306 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - B/op",
            "value": 121,
            "unit": "B/op",
            "extra": "4849306 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4849306 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc",
            "value": 251.5,
            "unit": "ns/op\t      16 B/op\t       2 allocs/op",
            "extra": "4761018 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - ns/op",
            "value": 251.5,
            "unit": "ns/op",
            "extra": "4761018 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - B/op",
            "value": 16,
            "unit": "B/op",
            "extra": "4761018 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - allocs/op",
            "value": 2,
            "unit": "allocs/op",
            "extra": "4761018 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint",
            "value": 1396,
            "unit": "ns/op\t      1000 datapoints\t     183 B/op\t       0 allocs/op",
            "extra": "867460 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - ns/op",
            "value": 1396,
            "unit": "ns/op",
            "extra": "867460 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - datapoints",
            "value": 1000,
            "unit": "datapoints",
            "extra": "867460 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - B/op",
            "value": 183,
            "unit": "B/op",
            "extra": "867460 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "867460 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation",
            "value": 218.6,
            "unit": "ns/op\t     126 B/op\t       0 allocs/op",
            "extra": "5486359 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - ns/op",
            "value": 218.6,
            "unit": "ns/op",
            "extra": "5486359 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - B/op",
            "value": 126,
            "unit": "B/op",
            "extra": "5486359 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "5486359 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData",
            "value": 238414,
            "unit": "ns/op\t  106801 B/op\t      13 allocs/op",
            "extra": "4918 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - ns/op",
            "value": 238414,
            "unit": "ns/op",
            "extra": "4918 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - B/op",
            "value": 106801,
            "unit": "B/op",
            "extra": "4918 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - allocs/op",
            "value": 13,
            "unit": "allocs/op",
            "extra": "4918 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small",
            "value": 21737,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "53500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - ns/op",
            "value": 21737,
            "unit": "ns/op",
            "extra": "53500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "53500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium",
            "value": 21764,
            "unit": "ns/op\t     730 B/op\t      59 allocs/op",
            "extra": "54379 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - ns/op",
            "value": 21764,
            "unit": "ns/op",
            "extra": "54379 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - B/op",
            "value": 730,
            "unit": "B/op",
            "extra": "54379 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54379 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large",
            "value": 22310,
            "unit": "ns/op\t     730 B/op\t      59 allocs/op",
            "extra": "53228 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - ns/op",
            "value": 22310,
            "unit": "ns/op",
            "extra": "53228 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - B/op",
            "value": 730,
            "unit": "B/op",
            "extra": "53228 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53228 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small",
            "value": 22050,
            "unit": "ns/op\t     703 B/op\t      60 allocs/op",
            "extra": "52638 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - ns/op",
            "value": 22050,
            "unit": "ns/op",
            "extra": "52638 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - B/op",
            "value": 703,
            "unit": "B/op",
            "extra": "52638 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52638 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium",
            "value": 22035,
            "unit": "ns/op\t     704 B/op\t      60 allocs/op",
            "extra": "52809 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - ns/op",
            "value": 22035,
            "unit": "ns/op",
            "extra": "52809 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - B/op",
            "value": 704,
            "unit": "B/op",
            "extra": "52809 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52809 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large",
            "value": 22363,
            "unit": "ns/op\t     704 B/op\t      60 allocs/op",
            "extra": "52940 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - ns/op",
            "value": 22363,
            "unit": "ns/op",
            "extra": "52940 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - B/op",
            "value": 704,
            "unit": "B/op",
            "extra": "52940 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52940 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small",
            "value": 23668,
            "unit": "ns/op\t     703 B/op\t      60 allocs/op",
            "extra": "54171 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - ns/op",
            "value": 23668,
            "unit": "ns/op",
            "extra": "54171 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - B/op",
            "value": 703,
            "unit": "B/op",
            "extra": "54171 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "54171 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium",
            "value": 22520,
            "unit": "ns/op\t     701 B/op\t      60 allocs/op",
            "extra": "53662 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - ns/op",
            "value": 22520,
            "unit": "ns/op",
            "extra": "53662 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - B/op",
            "value": 701,
            "unit": "B/op",
            "extra": "53662 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53662 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large",
            "value": 22803,
            "unit": "ns/op\t     707 B/op\t      60 allocs/op",
            "extra": "52131 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - ns/op",
            "value": 22803,
            "unit": "ns/op",
            "extra": "52131 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - B/op",
            "value": 707,
            "unit": "B/op",
            "extra": "52131 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52131 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small",
            "value": 20535,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "58866 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - ns/op",
            "value": 20535,
            "unit": "ns/op",
            "extra": "58866 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "58866 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58866 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium",
            "value": 20054,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "59958 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - ns/op",
            "value": 20054,
            "unit": "ns/op",
            "extra": "59958 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "59958 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59958 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large",
            "value": 20044,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "58102 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - ns/op",
            "value": 20044,
            "unit": "ns/op",
            "extra": "58102 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "58102 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58102 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small",
            "value": 20559,
            "unit": "ns/op\t     539 B/op\t      58 allocs/op",
            "extra": "57196 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - ns/op",
            "value": 20559,
            "unit": "ns/op",
            "extra": "57196 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - B/op",
            "value": 539,
            "unit": "B/op",
            "extra": "57196 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57196 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium",
            "value": 20392,
            "unit": "ns/op\t     545 B/op\t      58 allocs/op",
            "extra": "57319 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - ns/op",
            "value": 20392,
            "unit": "ns/op",
            "extra": "57319 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - B/op",
            "value": 545,
            "unit": "B/op",
            "extra": "57319 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57319 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large",
            "value": 20726,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "56410 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - ns/op",
            "value": 20726,
            "unit": "ns/op",
            "extra": "56410 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "56410 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "56410 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small",
            "value": 21143,
            "unit": "ns/op\t     539 B/op\t      58 allocs/op",
            "extra": "58884 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - ns/op",
            "value": 21143,
            "unit": "ns/op",
            "extra": "58884 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - B/op",
            "value": 539,
            "unit": "B/op",
            "extra": "58884 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58884 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium",
            "value": 20847,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "59022 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - ns/op",
            "value": 20847,
            "unit": "ns/op",
            "extra": "59022 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "59022 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "59022 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large",
            "value": 21134,
            "unit": "ns/op\t     547 B/op\t      58 allocs/op",
            "extra": "57951 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - ns/op",
            "value": 21134,
            "unit": "ns/op",
            "extra": "57951 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - B/op",
            "value": 547,
            "unit": "B/op",
            "extra": "57951 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57951 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small",
            "value": 20070,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "60908 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - ns/op",
            "value": 20070,
            "unit": "ns/op",
            "extra": "60908 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "60908 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60908 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium",
            "value": 20067,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "61345 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - ns/op",
            "value": 20067,
            "unit": "ns/op",
            "extra": "61345 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "61345 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "61345 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large",
            "value": 19789,
            "unit": "ns/op\t     536 B/op\t      57 allocs/op",
            "extra": "59052 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - ns/op",
            "value": 19789,
            "unit": "ns/op",
            "extra": "59052 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - B/op",
            "value": 536,
            "unit": "B/op",
            "extra": "59052 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59052 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small",
            "value": 20321,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "57393 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - ns/op",
            "value": 20321,
            "unit": "ns/op",
            "extra": "57393 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "57393 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57393 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium",
            "value": 20164,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "57790 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - ns/op",
            "value": 20164,
            "unit": "ns/op",
            "extra": "57790 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "57790 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57790 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large",
            "value": 20304,
            "unit": "ns/op\t     544 B/op\t      58 allocs/op",
            "extra": "56704 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - ns/op",
            "value": 20304,
            "unit": "ns/op",
            "extra": "56704 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - B/op",
            "value": 544,
            "unit": "B/op",
            "extra": "56704 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "56704 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small",
            "value": 20139,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "57314 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - ns/op",
            "value": 20139,
            "unit": "ns/op",
            "extra": "57314 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "57314 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57314 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium",
            "value": 20081,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "57225 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - ns/op",
            "value": 20081,
            "unit": "ns/op",
            "extra": "57225 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "57225 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57225 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large",
            "value": 20482,
            "unit": "ns/op\t     544 B/op\t      58 allocs/op",
            "extra": "57322 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - ns/op",
            "value": 20482,
            "unit": "ns/op",
            "extra": "57322 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - B/op",
            "value": 544,
            "unit": "B/op",
            "extra": "57322 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57322 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration",
            "value": 5.692,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "210479182 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - ns/op",
            "value": 5.692,
            "unit": "ns/op",
            "extra": "210479182 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "210479182 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "210479182 times\n4 procs"
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
            "value": 0.0000113,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling - ns/op",
            "value": 0.0000113,
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
            "value": 39754,
            "unit": "ns/op\t    1363 B/op\t     114 allocs/op",
            "extra": "29984 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - ns/op",
            "value": 39754,
            "unit": "ns/op",
            "extra": "29984 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - B/op",
            "value": 1363,
            "unit": "B/op",
            "extra": "29984 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "29984 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4",
            "value": 39654,
            "unit": "ns/op\t    1358 B/op\t     114 allocs/op",
            "extra": "30206 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - ns/op",
            "value": 39654,
            "unit": "ns/op",
            "extra": "30206 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - B/op",
            "value": 1358,
            "unit": "B/op",
            "extra": "30206 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30206 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8",
            "value": 39758,
            "unit": "ns/op\t    1362 B/op\t     114 allocs/op",
            "extra": "29928 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - ns/op",
            "value": 39758,
            "unit": "ns/op",
            "extra": "29928 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - B/op",
            "value": 1362,
            "unit": "B/op",
            "extra": "29928 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "29928 times\n4 procs"
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
            "value": 4e-7,
            "unit": "ns/op\t      3610 datapoints\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s - ns/op",
            "value": 4e-7,
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
            "value": 21062,
            "unit": "ns/op\t   53103 B/op\t      37 allocs/op",
            "extra": "56565 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - ns/op",
            "value": 21062,
            "unit": "ns/op",
            "extra": "56565 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - B/op",
            "value": 53103,
            "unit": "B/op",
            "extra": "56565 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "56565 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation",
            "value": 55.48,
            "unit": "ns/op\t        32.00 bytes/point\t       0 B/op\t       0 allocs/op",
            "extra": "21648680 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - ns/op",
            "value": 55.48,
            "unit": "ns/op",
            "extra": "21648680 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - bytes/point",
            "value": 32,
            "unit": "bytes/point",
            "extra": "21648680 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21648680 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21648680 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData",
            "value": 257383,
            "unit": "ns/op\t  123584 B/op\t      19 allocs/op",
            "extra": "4455 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - ns/op",
            "value": 257383,
            "unit": "ns/op",
            "extra": "4455 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - B/op",
            "value": 123584,
            "unit": "B/op",
            "extra": "4455 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - allocs/op",
            "value": 19,
            "unit": "allocs/op",
            "extra": "4455 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing",
            "value": 5624,
            "unit": "ns/op\t 213597000 packets/op\t       0 B/op\t       0 allocs/op",
            "extra": "213597 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - ns/op",
            "value": 5624,
            "unit": "ns/op",
            "extra": "213597 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - packets/op",
            "value": 213597000,
            "unit": "packets/op",
            "extra": "213597 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "213597 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "213597 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit",
            "value": 2.493,
            "unit": "ns/op\t       100.0 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "481123928 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - ns/op",
            "value": 2.493,
            "unit": "ns/op",
            "extra": "481123928 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allowed%",
            "value": 100,
            "unit": "allowed%",
            "extra": "481123928 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "481123928 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "481123928 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS",
            "value": 118,
            "unit": "ns/op\t         0.1278 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10168038 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - ns/op",
            "value": 118,
            "unit": "ns/op",
            "extra": "10168038 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allowed%",
            "value": 0.1278,
            "unit": "allowed%",
            "extra": "10168038 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10168038 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10168038 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS",
            "value": 118,
            "unit": "ns/op\t         1.278 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10183462 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - ns/op",
            "value": 118,
            "unit": "ns/op",
            "extra": "10183462 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allowed%",
            "value": 1.278,
            "unit": "allowed%",
            "extra": "10183462 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10183462 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10183462 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS",
            "value": 118.7,
            "unit": "ns/op\t        12.85 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10179867 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - ns/op",
            "value": 118.7,
            "unit": "ns/op",
            "extra": "10179867 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allowed%",
            "value": 12.85,
            "unit": "allowed%",
            "extra": "10179867 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10179867 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10179867 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool",
            "value": 323.8,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "3709471 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - ns/op",
            "value": 323.8,
            "unit": "ns/op",
            "extra": "3709471 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "3709471 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "3709471 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool",
            "value": 2592,
            "unit": "ns/op\t   14560 B/op\t       1 allocs/op",
            "extra": "471139 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - ns/op",
            "value": 2592,
            "unit": "ns/op",
            "extra": "471139 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - B/op",
            "value": 14560,
            "unit": "B/op",
            "extra": "471139 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "471139 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController",
            "value": 336.5,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3527830 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - ns/op",
            "value": 336.5,
            "unit": "ns/op",
            "extra": "3527830 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3527830 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3527830 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64",
            "value": 5.298,
            "unit": "ns/op\t12079.43 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226488602 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - ns/op",
            "value": 5.298,
            "unit": "ns/op",
            "extra": "226488602 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - MB/s",
            "value": 12079.43,
            "unit": "MB/s",
            "extra": "226488602 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226488602 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226488602 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256",
            "value": 5.296,
            "unit": "ns/op\t48336.73 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226639250 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - ns/op",
            "value": 5.296,
            "unit": "ns/op",
            "extra": "226639250 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - MB/s",
            "value": 48336.73,
            "unit": "MB/s",
            "extra": "226639250 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226639250 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226639250 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512",
            "value": 5.307,
            "unit": "ns/op\t96467.71 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226447448 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - ns/op",
            "value": 5.307,
            "unit": "ns/op",
            "extra": "226447448 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - MB/s",
            "value": 96467.71,
            "unit": "MB/s",
            "extra": "226447448 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226447448 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226447448 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024",
            "value": 5.295,
            "unit": "ns/op\t193371.98 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226484107 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - ns/op",
            "value": 5.295,
            "unit": "ns/op",
            "extra": "226484107 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - MB/s",
            "value": 193371.98,
            "unit": "MB/s",
            "extra": "226484107 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226484107 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226484107 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500",
            "value": 5.292,
            "unit": "ns/op\t283452.68 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "221195322 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - ns/op",
            "value": 5.292,
            "unit": "ns/op",
            "extra": "221195322 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - MB/s",
            "value": 283452.68,
            "unit": "MB/s",
            "extra": "221195322 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "221195322 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "221195322 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000",
            "value": 5.297,
            "unit": "ns/op\t1699128.38 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226600033 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - ns/op",
            "value": 5.297,
            "unit": "ns/op",
            "extra": "226600033 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - MB/s",
            "value": 1699128.38,
            "unit": "MB/s",
            "extra": "226600033 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226600033 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226600033 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline",
            "value": 54934,
            "unit": "ns/op\t         0 MB/op\t       0 B/op\t       0 allocs/op",
            "extra": "21903 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - ns/op",
            "value": 54934,
            "unit": "ns/op",
            "extra": "21903 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - MB/op",
            "value": 0,
            "unit": "MB/op",
            "extra": "21903 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21903 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21903 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple",
            "value": 92.54,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "13255527 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - ns/op",
            "value": 92.54,
            "unit": "ns/op",
            "extra": "13255527 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "13255527 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "13255527 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID",
            "value": 276,
            "unit": "ns/op\t      61 B/op\t       3 allocs/op",
            "extra": "4288615 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - ns/op",
            "value": 276,
            "unit": "ns/op",
            "extra": "4288615 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - B/op",
            "value": 61,
            "unit": "B/op",
            "extra": "4288615 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "4288615 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket",
            "value": 286.4,
            "unit": "ns/op\t    3508 B/op\t       0 allocs/op",
            "extra": "4829928 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - ns/op",
            "value": 286.4,
            "unit": "ns/op",
            "extra": "4829928 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - B/op",
            "value": 3508,
            "unit": "B/op",
            "extra": "4829928 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4829928 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small",
            "value": 22167,
            "unit": "ns/op\t     728 B/op\t      59 allocs/op",
            "extra": "53800 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - ns/op",
            "value": 22167,
            "unit": "ns/op",
            "extra": "53800 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - B/op",
            "value": 728,
            "unit": "B/op",
            "extra": "53800 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53800 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium",
            "value": 22193,
            "unit": "ns/op\t     726 B/op\t      59 allocs/op",
            "extra": "53538 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - ns/op",
            "value": 22193,
            "unit": "ns/op",
            "extra": "53538 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - B/op",
            "value": 726,
            "unit": "B/op",
            "extra": "53538 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53538 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large",
            "value": 22198,
            "unit": "ns/op\t     724 B/op\t      59 allocs/op",
            "extra": "53664 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - ns/op",
            "value": 22198,
            "unit": "ns/op",
            "extra": "53664 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - B/op",
            "value": 724,
            "unit": "B/op",
            "extra": "53664 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53664 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small",
            "value": 20127,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "59228 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - ns/op",
            "value": 20127,
            "unit": "ns/op",
            "extra": "59228 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "59228 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59228 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium",
            "value": 20351,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58725 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - ns/op",
            "value": 20351,
            "unit": "ns/op",
            "extra": "58725 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58725 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58725 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large",
            "value": 20244,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58311 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - ns/op",
            "value": 20244,
            "unit": "ns/op",
            "extra": "58311 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58311 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58311 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small",
            "value": 20034,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "59253 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - ns/op",
            "value": 20034,
            "unit": "ns/op",
            "extra": "59253 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "59253 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59253 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium",
            "value": 20046,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "58962 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - ns/op",
            "value": 20046,
            "unit": "ns/op",
            "extra": "58962 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "58962 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58962 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large",
            "value": 20155,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "58948 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - ns/op",
            "value": 20155,
            "unit": "ns/op",
            "extra": "58948 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "58948 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58948 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix",
            "value": 43040,
            "unit": "ns/op\t   28619 B/op\t     341 allocs/op",
            "extra": "24765 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - ns/op",
            "value": 43040,
            "unit": "ns/op",
            "extra": "24765 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - B/op",
            "value": 28619,
            "unit": "B/op",
            "extra": "24765 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - allocs/op",
            "value": 341,
            "unit": "allocs/op",
            "extra": "24765 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap",
            "value": 6336,
            "unit": "ns/op\t    3696 B/op\t      52 allocs/op",
            "extra": "184144 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - ns/op",
            "value": 6336,
            "unit": "ns/op",
            "extra": "184144 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - B/op",
            "value": 3696,
            "unit": "B/op",
            "extra": "184144 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - allocs/op",
            "value": 52,
            "unit": "allocs/op",
            "extra": "184144 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer",
            "value": 9607,
            "unit": "ns/op\t    7257 B/op\t      34 allocs/op",
            "extra": "121884 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - ns/op",
            "value": 9607,
            "unit": "ns/op",
            "extra": "121884 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - B/op",
            "value": 7257,
            "unit": "B/op",
            "extra": "121884 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - allocs/op",
            "value": 34,
            "unit": "allocs/op",
            "extra": "121884 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey",
            "value": 2360,
            "unit": "ns/op\t    1400 B/op\t      27 allocs/op",
            "extra": "507128 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - ns/op",
            "value": 2360,
            "unit": "ns/op",
            "extra": "507128 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - B/op",
            "value": 1400,
            "unit": "B/op",
            "extra": "507128 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "507128 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial",
            "value": 16567,
            "unit": "ns/op\t   16466 B/op\t      98 allocs/op",
            "extra": "70092 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - ns/op",
            "value": 16567,
            "unit": "ns/op",
            "extra": "70092 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - B/op",
            "value": 16466,
            "unit": "B/op",
            "extra": "70092 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - allocs/op",
            "value": 98,
            "unit": "allocs/op",
            "extra": "70092 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor",
            "value": 8.739,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "137483563 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - ns/op",
            "value": 8.739,
            "unit": "ns/op",
            "extra": "137483563 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "137483563 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "137483563 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor",
            "value": 24.16,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "49328938 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - ns/op",
            "value": 24.16,
            "unit": "ns/op",
            "extra": "49328938 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "49328938 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "49328938 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex",
            "value": 36.24,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "33171313 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - ns/op",
            "value": 36.24,
            "unit": "ns/op",
            "extra": "33171313 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "33171313 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "33171313 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow",
            "value": 6.547,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "182792545 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - ns/op",
            "value": 6.547,
            "unit": "ns/op",
            "extra": "182792545 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "182792545 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "182792545 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse",
            "value": 18.56,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "64592200 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - ns/op",
            "value": 18.56,
            "unit": "ns/op",
            "extra": "64592200 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "64592200 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "64592200 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire",
            "value": 5.911,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "202783840 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - ns/op",
            "value": 5.911,
            "unit": "ns/op",
            "extra": "202783840 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "202783840 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "202783840 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix",
            "value": 3.747,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "320699834 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - ns/op",
            "value": 3.747,
            "unit": "ns/op",
            "extra": "320699834 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "320699834 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "320699834 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave",
            "value": 32.27,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "36661502 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - ns/op",
            "value": 32.27,
            "unit": "ns/op",
            "extra": "36661502 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "36661502 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "36661502 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle",
            "value": 3.743,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "321350937 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - ns/op",
            "value": 3.743,
            "unit": "ns/op",
            "extra": "321350937 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "321350937 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "321350937 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10",
            "value": 102597,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10 - ns/op",
            "value": 102597,
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
            "value": 102848,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - ns/op",
            "value": 102848,
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
            "value": 102739,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000 - ns/op",
            "value": 102739,
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
            "extra": "2703151 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - ns/op",
            "value": 442.3,
            "unit": "ns/op",
            "extra": "2703151 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - B/op",
            "value": 229,
            "unit": "B/op",
            "extra": "2703151 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2703151 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2",
            "value": 8992,
            "unit": "ns/op\t   17464 B/op\t      77 allocs/op",
            "extra": "129946 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - ns/op",
            "value": 8992,
            "unit": "ns/op",
            "extra": "129946 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - B/op",
            "value": 17464,
            "unit": "B/op",
            "extra": "129946 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - allocs/op",
            "value": 77,
            "unit": "allocs/op",
            "extra": "129946 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3",
            "value": 24875,
            "unit": "ns/op\t   47576 B/op\t     200 allocs/op",
            "extra": "47832 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - ns/op",
            "value": 24875,
            "unit": "ns/op",
            "extra": "47832 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - B/op",
            "value": 47576,
            "unit": "B/op",
            "extra": "47832 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - allocs/op",
            "value": 200,
            "unit": "allocs/op",
            "extra": "47832 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4",
            "value": 35905,
            "unit": "ns/op\t   69816 B/op\t     295 allocs/op",
            "extra": "33535 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - ns/op",
            "value": 35905,
            "unit": "ns/op",
            "extra": "33535 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - B/op",
            "value": 69816,
            "unit": "B/op",
            "extra": "33535 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - allocs/op",
            "value": 295,
            "unit": "allocs/op",
            "extra": "33535 times\n4 procs"
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
          "id": "397cafccbdd277df3c66f4ed0b64ab30ef6f8c50",
          "message": "ci: remove broken Documentation job",
          "timestamp": "2026-02-18T12:42:12Z",
          "url": "https://github.com/perplext/nsd/pull/49/commits/397cafccbdd277df3c66f4ed0b64ab30ef6f8c50"
        },
        "date": 1771420405668,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkProcessTLSPacket",
            "value": 611.8,
            "unit": "ns/op\t     208 B/op\t       8 allocs/op",
            "extra": "1838184 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - ns/op",
            "value": 611.8,
            "unit": "ns/op",
            "extra": "1838184 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - B/op",
            "value": 208,
            "unit": "B/op",
            "extra": "1838184 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1838184 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes",
            "value": 7145,
            "unit": "ns/op\t    1588 B/op\t      93 allocs/op",
            "extra": "167750 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - ns/op",
            "value": 7145,
            "unit": "ns/op",
            "extra": "167750 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - B/op",
            "value": 1588,
            "unit": "B/op",
            "extra": "167750 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - allocs/op",
            "value": 93,
            "unit": "allocs/op",
            "extra": "167750 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint",
            "value": 166.9,
            "unit": "ns/op\t      60 B/op\t       0 allocs/op",
            "extra": "7296355 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - ns/op",
            "value": 166.9,
            "unit": "ns/op",
            "extra": "7296355 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - B/op",
            "value": 60,
            "unit": "B/op",
            "extra": "7296355 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "7296355 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint",
            "value": 256.3,
            "unit": "ns/op\t     121 B/op\t       0 allocs/op",
            "extra": "4661817 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - ns/op",
            "value": 256.3,
            "unit": "ns/op",
            "extra": "4661817 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - B/op",
            "value": 121,
            "unit": "B/op",
            "extra": "4661817 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4661817 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc",
            "value": 254.7,
            "unit": "ns/op\t      16 B/op\t       2 allocs/op",
            "extra": "4649581 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - ns/op",
            "value": 254.7,
            "unit": "ns/op",
            "extra": "4649581 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - B/op",
            "value": 16,
            "unit": "B/op",
            "extra": "4649581 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - allocs/op",
            "value": 2,
            "unit": "allocs/op",
            "extra": "4649581 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint",
            "value": 1405,
            "unit": "ns/op\t      1000 datapoints\t     183 B/op\t       0 allocs/op",
            "extra": "833959 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - ns/op",
            "value": 1405,
            "unit": "ns/op",
            "extra": "833959 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - datapoints",
            "value": 1000,
            "unit": "datapoints",
            "extra": "833959 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - B/op",
            "value": 183,
            "unit": "B/op",
            "extra": "833959 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "833959 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation",
            "value": 226.8,
            "unit": "ns/op\t     126 B/op\t       0 allocs/op",
            "extra": "5294500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - ns/op",
            "value": 226.8,
            "unit": "ns/op",
            "extra": "5294500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - B/op",
            "value": 126,
            "unit": "B/op",
            "extra": "5294500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "5294500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData",
            "value": 245091,
            "unit": "ns/op\t  106801 B/op\t      13 allocs/op",
            "extra": "4532 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - ns/op",
            "value": 245091,
            "unit": "ns/op",
            "extra": "4532 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - B/op",
            "value": 106801,
            "unit": "B/op",
            "extra": "4532 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - allocs/op",
            "value": 13,
            "unit": "allocs/op",
            "extra": "4532 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small",
            "value": 21862,
            "unit": "ns/op\t     727 B/op\t      59 allocs/op",
            "extra": "53206 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - ns/op",
            "value": 21862,
            "unit": "ns/op",
            "extra": "53206 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - B/op",
            "value": 727,
            "unit": "B/op",
            "extra": "53206 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53206 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium",
            "value": 22264,
            "unit": "ns/op\t     727 B/op\t      59 allocs/op",
            "extra": "54290 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - ns/op",
            "value": 22264,
            "unit": "ns/op",
            "extra": "54290 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - B/op",
            "value": 727,
            "unit": "B/op",
            "extra": "54290 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54290 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large",
            "value": 22362,
            "unit": "ns/op\t     728 B/op\t      59 allocs/op",
            "extra": "54254 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - ns/op",
            "value": 22362,
            "unit": "ns/op",
            "extra": "54254 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - B/op",
            "value": 728,
            "unit": "B/op",
            "extra": "54254 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54254 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small",
            "value": 22419,
            "unit": "ns/op\t     701 B/op\t      60 allocs/op",
            "extra": "53954 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - ns/op",
            "value": 22419,
            "unit": "ns/op",
            "extra": "53954 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - B/op",
            "value": 701,
            "unit": "B/op",
            "extra": "53954 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53954 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium",
            "value": 22140,
            "unit": "ns/op\t     704 B/op\t      60 allocs/op",
            "extra": "53097 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - ns/op",
            "value": 22140,
            "unit": "ns/op",
            "extra": "53097 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - B/op",
            "value": 704,
            "unit": "B/op",
            "extra": "53097 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53097 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large",
            "value": 22407,
            "unit": "ns/op\t     704 B/op\t      60 allocs/op",
            "extra": "53034 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - ns/op",
            "value": 22407,
            "unit": "ns/op",
            "extra": "53034 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - B/op",
            "value": 704,
            "unit": "B/op",
            "extra": "53034 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53034 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small",
            "value": 22219,
            "unit": "ns/op\t     702 B/op\t      60 allocs/op",
            "extra": "52686 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - ns/op",
            "value": 22219,
            "unit": "ns/op",
            "extra": "52686 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - B/op",
            "value": 702,
            "unit": "B/op",
            "extra": "52686 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52686 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium",
            "value": 22377,
            "unit": "ns/op\t     705 B/op\t      60 allocs/op",
            "extra": "53275 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - ns/op",
            "value": 22377,
            "unit": "ns/op",
            "extra": "53275 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - B/op",
            "value": 705,
            "unit": "B/op",
            "extra": "53275 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53275 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large",
            "value": 22379,
            "unit": "ns/op\t     706 B/op\t      60 allocs/op",
            "extra": "52929 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - ns/op",
            "value": 22379,
            "unit": "ns/op",
            "extra": "52929 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - B/op",
            "value": 706,
            "unit": "B/op",
            "extra": "52929 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52929 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small",
            "value": 19779,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "58647 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - ns/op",
            "value": 19779,
            "unit": "ns/op",
            "extra": "58647 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "58647 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58647 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium",
            "value": 20104,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "59178 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - ns/op",
            "value": 20104,
            "unit": "ns/op",
            "extra": "59178 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "59178 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59178 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large",
            "value": 20068,
            "unit": "ns/op\t     538 B/op\t      57 allocs/op",
            "extra": "59389 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - ns/op",
            "value": 20068,
            "unit": "ns/op",
            "extra": "59389 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - B/op",
            "value": 538,
            "unit": "B/op",
            "extra": "59389 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59389 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small",
            "value": 20969,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "58376 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - ns/op",
            "value": 20969,
            "unit": "ns/op",
            "extra": "58376 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "58376 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58376 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium",
            "value": 20896,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "58214 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - ns/op",
            "value": 20896,
            "unit": "ns/op",
            "extra": "58214 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "58214 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58214 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large",
            "value": 20884,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58243 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - ns/op",
            "value": 20884,
            "unit": "ns/op",
            "extra": "58243 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58243 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58243 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small",
            "value": 20709,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "58809 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - ns/op",
            "value": 20709,
            "unit": "ns/op",
            "extra": "58809 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "58809 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58809 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium",
            "value": 20700,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58732 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - ns/op",
            "value": 20700,
            "unit": "ns/op",
            "extra": "58732 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58732 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58732 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large",
            "value": 20870,
            "unit": "ns/op\t     544 B/op\t      58 allocs/op",
            "extra": "58371 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - ns/op",
            "value": 20870,
            "unit": "ns/op",
            "extra": "58371 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - B/op",
            "value": 544,
            "unit": "B/op",
            "extra": "58371 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58371 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small",
            "value": 19644,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "60649 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - ns/op",
            "value": 19644,
            "unit": "ns/op",
            "extra": "60649 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "60649 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60649 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium",
            "value": 19616,
            "unit": "ns/op\t     535 B/op\t      57 allocs/op",
            "extra": "59372 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - ns/op",
            "value": 19616,
            "unit": "ns/op",
            "extra": "59372 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - B/op",
            "value": 535,
            "unit": "B/op",
            "extra": "59372 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59372 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large",
            "value": 19851,
            "unit": "ns/op\t     537 B/op\t      57 allocs/op",
            "extra": "58648 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - ns/op",
            "value": 19851,
            "unit": "ns/op",
            "extra": "58648 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - B/op",
            "value": 537,
            "unit": "B/op",
            "extra": "58648 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58648 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small",
            "value": 20613,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "58965 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - ns/op",
            "value": 20613,
            "unit": "ns/op",
            "extra": "58965 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "58965 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58965 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium",
            "value": 20657,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58957 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - ns/op",
            "value": 20657,
            "unit": "ns/op",
            "extra": "58957 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58957 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58957 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large",
            "value": 20794,
            "unit": "ns/op\t     545 B/op\t      58 allocs/op",
            "extra": "58621 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - ns/op",
            "value": 20794,
            "unit": "ns/op",
            "extra": "58621 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - B/op",
            "value": 545,
            "unit": "B/op",
            "extra": "58621 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58621 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small",
            "value": 20606,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "58935 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - ns/op",
            "value": 20606,
            "unit": "ns/op",
            "extra": "58935 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "58935 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58935 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium",
            "value": 20331,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "57991 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - ns/op",
            "value": 20331,
            "unit": "ns/op",
            "extra": "57991 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "57991 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57991 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large",
            "value": 20458,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "57399 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - ns/op",
            "value": 20458,
            "unit": "ns/op",
            "extra": "57399 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "57399 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57399 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration",
            "value": 5.696,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "210439018 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - ns/op",
            "value": 5.696,
            "unit": "ns/op",
            "extra": "210439018 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "210439018 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "210439018 times\n4 procs"
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
            "value": 0.0000107,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling - ns/op",
            "value": 0.0000107,
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
            "value": 40060,
            "unit": "ns/op\t    1364 B/op\t     114 allocs/op",
            "extra": "29876 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - ns/op",
            "value": 40060,
            "unit": "ns/op",
            "extra": "29876 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - B/op",
            "value": 1364,
            "unit": "B/op",
            "extra": "29876 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "29876 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4",
            "value": 40317,
            "unit": "ns/op\t    1362 B/op\t     114 allocs/op",
            "extra": "29910 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - ns/op",
            "value": 40317,
            "unit": "ns/op",
            "extra": "29910 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - B/op",
            "value": 1362,
            "unit": "B/op",
            "extra": "29910 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "29910 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8",
            "value": 40066,
            "unit": "ns/op\t    1365 B/op\t     114 allocs/op",
            "extra": "29960 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - ns/op",
            "value": 40066,
            "unit": "ns/op",
            "extra": "29960 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - B/op",
            "value": 1365,
            "unit": "B/op",
            "extra": "29960 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "29960 times\n4 procs"
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
            "value": 3e-7,
            "unit": "ns/op\t      3610 datapoints\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s - ns/op",
            "value": 3e-7,
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
            "value": 21561,
            "unit": "ns/op\t   53170 B/op\t      37 allocs/op",
            "extra": "55120 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - ns/op",
            "value": 21561,
            "unit": "ns/op",
            "extra": "55120 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - B/op",
            "value": 53170,
            "unit": "B/op",
            "extra": "55120 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "55120 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation",
            "value": 55.6,
            "unit": "ns/op\t        32.00 bytes/point\t       0 B/op\t       0 allocs/op",
            "extra": "21634068 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - ns/op",
            "value": 55.6,
            "unit": "ns/op",
            "extra": "21634068 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - bytes/point",
            "value": 32,
            "unit": "bytes/point",
            "extra": "21634068 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21634068 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21634068 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData",
            "value": 264459,
            "unit": "ns/op\t  123584 B/op\t      19 allocs/op",
            "extra": "4292 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - ns/op",
            "value": 264459,
            "unit": "ns/op",
            "extra": "4292 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - B/op",
            "value": 123584,
            "unit": "B/op",
            "extra": "4292 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - allocs/op",
            "value": 19,
            "unit": "allocs/op",
            "extra": "4292 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing",
            "value": 5619,
            "unit": "ns/op\t 213418000 packets/op\t       0 B/op\t       0 allocs/op",
            "extra": "213418 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - ns/op",
            "value": 5619,
            "unit": "ns/op",
            "extra": "213418 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - packets/op",
            "value": 213418000,
            "unit": "packets/op",
            "extra": "213418 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "213418 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "213418 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit",
            "value": 2.497,
            "unit": "ns/op\t       100.0 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "481934104 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - ns/op",
            "value": 2.497,
            "unit": "ns/op",
            "extra": "481934104 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allowed%",
            "value": 100,
            "unit": "allowed%",
            "extra": "481934104 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "481934104 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "481934104 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS",
            "value": 118.3,
            "unit": "ns/op\t         0.1281 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10137804 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - ns/op",
            "value": 118.3,
            "unit": "ns/op",
            "extra": "10137804 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allowed%",
            "value": 0.1281,
            "unit": "allowed%",
            "extra": "10137804 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10137804 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10137804 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS",
            "value": 118.3,
            "unit": "ns/op\t         1.282 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10178640 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - ns/op",
            "value": 118.3,
            "unit": "ns/op",
            "extra": "10178640 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allowed%",
            "value": 1.282,
            "unit": "allowed%",
            "extra": "10178640 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10178640 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10178640 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS",
            "value": 118.9,
            "unit": "ns/op\t        12.87 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10139330 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - ns/op",
            "value": 118.9,
            "unit": "ns/op",
            "extra": "10139330 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allowed%",
            "value": 12.87,
            "unit": "allowed%",
            "extra": "10139330 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10139330 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10139330 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool",
            "value": 328,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "3654654 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - ns/op",
            "value": 328,
            "unit": "ns/op",
            "extra": "3654654 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "3654654 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "3654654 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool",
            "value": 3040,
            "unit": "ns/op\t   14560 B/op\t       1 allocs/op",
            "extra": "397386 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - ns/op",
            "value": 3040,
            "unit": "ns/op",
            "extra": "397386 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - B/op",
            "value": 14560,
            "unit": "B/op",
            "extra": "397386 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "397386 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController",
            "value": 340.7,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3496669 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - ns/op",
            "value": 340.7,
            "unit": "ns/op",
            "extra": "3496669 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3496669 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3496669 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64",
            "value": 5.299,
            "unit": "ns/op\t12077.06 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226190916 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - ns/op",
            "value": 5.299,
            "unit": "ns/op",
            "extra": "226190916 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - MB/s",
            "value": 12077.06,
            "unit": "MB/s",
            "extra": "226190916 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226190916 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226190916 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256",
            "value": 5.3,
            "unit": "ns/op\t48300.39 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226564299 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - ns/op",
            "value": 5.3,
            "unit": "ns/op",
            "extra": "226564299 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - MB/s",
            "value": 48300.39,
            "unit": "MB/s",
            "extra": "226564299 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226564299 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226564299 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512",
            "value": 5.296,
            "unit": "ns/op\t96671.33 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "224999371 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - ns/op",
            "value": 5.296,
            "unit": "ns/op",
            "extra": "224999371 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - MB/s",
            "value": 96671.33,
            "unit": "MB/s",
            "extra": "224999371 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "224999371 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "224999371 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024",
            "value": 5.293,
            "unit": "ns/op\t193464.12 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226345086 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - ns/op",
            "value": 5.293,
            "unit": "ns/op",
            "extra": "226345086 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - MB/s",
            "value": 193464.12,
            "unit": "MB/s",
            "extra": "226345086 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226345086 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226345086 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500",
            "value": 5.298,
            "unit": "ns/op\t283131.13 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226515847 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - ns/op",
            "value": 5.298,
            "unit": "ns/op",
            "extra": "226515847 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - MB/s",
            "value": 283131.13,
            "unit": "MB/s",
            "extra": "226515847 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226515847 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226515847 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000",
            "value": 5.304,
            "unit": "ns/op\t1696705.28 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "225244513 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - ns/op",
            "value": 5.304,
            "unit": "ns/op",
            "extra": "225244513 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - MB/s",
            "value": 1696705.28,
            "unit": "MB/s",
            "extra": "225244513 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "225244513 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "225244513 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline",
            "value": 54675,
            "unit": "ns/op\t         0 MB/op\t       0 B/op\t       0 allocs/op",
            "extra": "21860 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - ns/op",
            "value": 54675,
            "unit": "ns/op",
            "extra": "21860 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - MB/op",
            "value": 0,
            "unit": "MB/op",
            "extra": "21860 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21860 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21860 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple",
            "value": 92.42,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "13170454 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - ns/op",
            "value": 92.42,
            "unit": "ns/op",
            "extra": "13170454 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "13170454 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "13170454 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID",
            "value": 282.2,
            "unit": "ns/op\t      61 B/op\t       3 allocs/op",
            "extra": "4206018 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - ns/op",
            "value": 282.2,
            "unit": "ns/op",
            "extra": "4206018 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - B/op",
            "value": 61,
            "unit": "B/op",
            "extra": "4206018 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "4206018 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket",
            "value": 348,
            "unit": "ns/op\t    4013 B/op\t       0 allocs/op",
            "extra": "4222124 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - ns/op",
            "value": 348,
            "unit": "ns/op",
            "extra": "4222124 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - B/op",
            "value": 4013,
            "unit": "B/op",
            "extra": "4222124 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4222124 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small",
            "value": 22218,
            "unit": "ns/op\t     724 B/op\t      59 allocs/op",
            "extra": "53496 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - ns/op",
            "value": 22218,
            "unit": "ns/op",
            "extra": "53496 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - B/op",
            "value": 724,
            "unit": "B/op",
            "extra": "53496 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53496 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium",
            "value": 22259,
            "unit": "ns/op\t     723 B/op\t      59 allocs/op",
            "extra": "53032 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - ns/op",
            "value": 22259,
            "unit": "ns/op",
            "extra": "53032 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - B/op",
            "value": 723,
            "unit": "B/op",
            "extra": "53032 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53032 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large",
            "value": 22209,
            "unit": "ns/op\t     724 B/op\t      59 allocs/op",
            "extra": "53929 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - ns/op",
            "value": 22209,
            "unit": "ns/op",
            "extra": "53929 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - B/op",
            "value": 724,
            "unit": "B/op",
            "extra": "53929 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53929 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small",
            "value": 20479,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "58642 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - ns/op",
            "value": 20479,
            "unit": "ns/op",
            "extra": "58642 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "58642 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58642 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium",
            "value": 20198,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "58561 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - ns/op",
            "value": 20198,
            "unit": "ns/op",
            "extra": "58561 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "58561 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58561 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large",
            "value": 20296,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58689 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - ns/op",
            "value": 20296,
            "unit": "ns/op",
            "extra": "58689 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58689 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58689 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small",
            "value": 20131,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58386 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - ns/op",
            "value": 20131,
            "unit": "ns/op",
            "extra": "58386 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58386 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58386 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium",
            "value": 20116,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "59512 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - ns/op",
            "value": 20116,
            "unit": "ns/op",
            "extra": "59512 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "59512 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59512 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large",
            "value": 20164,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "58656 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - ns/op",
            "value": 20164,
            "unit": "ns/op",
            "extra": "58656 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "58656 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58656 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix",
            "value": 45040,
            "unit": "ns/op\t   28523 B/op\t     335 allocs/op",
            "extra": "24985 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - ns/op",
            "value": 45040,
            "unit": "ns/op",
            "extra": "24985 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - B/op",
            "value": 28523,
            "unit": "B/op",
            "extra": "24985 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - allocs/op",
            "value": 335,
            "unit": "allocs/op",
            "extra": "24985 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap",
            "value": 6803,
            "unit": "ns/op\t    3696 B/op\t      52 allocs/op",
            "extra": "173840 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - ns/op",
            "value": 6803,
            "unit": "ns/op",
            "extra": "173840 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - B/op",
            "value": 3696,
            "unit": "B/op",
            "extra": "173840 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - allocs/op",
            "value": 52,
            "unit": "allocs/op",
            "extra": "173840 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer",
            "value": 10395,
            "unit": "ns/op\t    7257 B/op\t      34 allocs/op",
            "extra": "114940 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - ns/op",
            "value": 10395,
            "unit": "ns/op",
            "extra": "114940 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - B/op",
            "value": 7257,
            "unit": "B/op",
            "extra": "114940 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - allocs/op",
            "value": 34,
            "unit": "allocs/op",
            "extra": "114940 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey",
            "value": 2511,
            "unit": "ns/op\t    1400 B/op\t      27 allocs/op",
            "extra": "424848 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - ns/op",
            "value": 2511,
            "unit": "ns/op",
            "extra": "424848 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - B/op",
            "value": 1400,
            "unit": "B/op",
            "extra": "424848 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "424848 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial",
            "value": 17969,
            "unit": "ns/op\t   16466 B/op\t      98 allocs/op",
            "extra": "65826 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - ns/op",
            "value": 17969,
            "unit": "ns/op",
            "extra": "65826 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - B/op",
            "value": 16466,
            "unit": "B/op",
            "extra": "65826 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - allocs/op",
            "value": 98,
            "unit": "allocs/op",
            "extra": "65826 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor",
            "value": 8.743,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "137265986 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - ns/op",
            "value": 8.743,
            "unit": "ns/op",
            "extra": "137265986 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "137265986 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "137265986 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor",
            "value": 24.16,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "49646319 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - ns/op",
            "value": 24.16,
            "unit": "ns/op",
            "extra": "49646319 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "49646319 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "49646319 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex",
            "value": 37.08,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "33156145 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - ns/op",
            "value": 37.08,
            "unit": "ns/op",
            "extra": "33156145 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "33156145 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "33156145 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow",
            "value": 6.547,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "182958574 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - ns/op",
            "value": 6.547,
            "unit": "ns/op",
            "extra": "182958574 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "182958574 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "182958574 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse",
            "value": 18.56,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "65045857 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - ns/op",
            "value": 18.56,
            "unit": "ns/op",
            "extra": "65045857 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "65045857 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "65045857 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire",
            "value": 5.928,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "202787856 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - ns/op",
            "value": 5.928,
            "unit": "ns/op",
            "extra": "202787856 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "202787856 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "202787856 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix",
            "value": 3.75,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "319910061 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - ns/op",
            "value": 3.75,
            "unit": "ns/op",
            "extra": "319910061 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "319910061 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "319910061 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave",
            "value": 32.89,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "36584542 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - ns/op",
            "value": 32.89,
            "unit": "ns/op",
            "extra": "36584542 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "36584542 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "36584542 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle",
            "value": 3.743,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "320968640 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - ns/op",
            "value": 3.743,
            "unit": "ns/op",
            "extra": "320968640 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "320968640 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "320968640 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10",
            "value": 103747,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10 - ns/op",
            "value": 103747,
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
            "value": 103597,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - ns/op",
            "value": 103597,
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
            "value": 103953,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000 - ns/op",
            "value": 103953,
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
            "value": 461.9,
            "unit": "ns/op\t     229 B/op\t       3 allocs/op",
            "extra": "2597139 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - ns/op",
            "value": 461.9,
            "unit": "ns/op",
            "extra": "2597139 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - B/op",
            "value": 229,
            "unit": "B/op",
            "extra": "2597139 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2597139 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2",
            "value": 10655,
            "unit": "ns/op\t   17464 B/op\t      77 allocs/op",
            "extra": "106599 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - ns/op",
            "value": 10655,
            "unit": "ns/op",
            "extra": "106599 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - B/op",
            "value": 17464,
            "unit": "B/op",
            "extra": "106599 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - allocs/op",
            "value": 77,
            "unit": "allocs/op",
            "extra": "106599 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3",
            "value": 28379,
            "unit": "ns/op\t   47576 B/op\t     200 allocs/op",
            "extra": "42352 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - ns/op",
            "value": 28379,
            "unit": "ns/op",
            "extra": "42352 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - B/op",
            "value": 47576,
            "unit": "B/op",
            "extra": "42352 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - allocs/op",
            "value": 200,
            "unit": "allocs/op",
            "extra": "42352 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4",
            "value": 40736,
            "unit": "ns/op\t   69816 B/op\t     295 allocs/op",
            "extra": "29704 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - ns/op",
            "value": 40736,
            "unit": "ns/op",
            "extra": "29704 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - B/op",
            "value": 69816,
            "unit": "B/op",
            "extra": "29704 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - allocs/op",
            "value": 295,
            "unit": "allocs/op",
            "extra": "29704 times\n4 procs"
          }
        ]
      },
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
          "id": "b7a4e291f970eeaca6574f43a1e2b021c40087d4",
          "message": "ci: remove broken Documentation job (#49)\n\nThe godoc tool is deprecated (v0.1.0-deprecated) and returns 404 for\nmodule-based packages. This job failed on every push to main.\n\nAPI docs are auto-available at pkg.go.dev/github.com/perplext/nsd.",
          "timestamp": "2026-02-18T08:09:27-05:00",
          "tree_id": "68f77a81fda79aac7fd419a74e4e83990d3734d6",
          "url": "https://github.com/perplext/nsd/commit/b7a4e291f970eeaca6574f43a1e2b021c40087d4"
        },
        "date": 1771420428986,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkProcessTLSPacket",
            "value": 602.6,
            "unit": "ns/op\t     208 B/op\t       8 allocs/op",
            "extra": "1987143 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - ns/op",
            "value": 602.6,
            "unit": "ns/op",
            "extra": "1987143 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - B/op",
            "value": 208,
            "unit": "B/op",
            "extra": "1987143 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1987143 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes",
            "value": 7052,
            "unit": "ns/op\t    1588 B/op\t      93 allocs/op",
            "extra": "164428 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - ns/op",
            "value": 7052,
            "unit": "ns/op",
            "extra": "164428 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - B/op",
            "value": 1588,
            "unit": "B/op",
            "extra": "164428 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - allocs/op",
            "value": 93,
            "unit": "allocs/op",
            "extra": "164428 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint",
            "value": 162.1,
            "unit": "ns/op\t      60 B/op\t       0 allocs/op",
            "extra": "7436434 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - ns/op",
            "value": 162.1,
            "unit": "ns/op",
            "extra": "7436434 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - B/op",
            "value": 60,
            "unit": "B/op",
            "extra": "7436434 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "7436434 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint",
            "value": 248.4,
            "unit": "ns/op\t     121 B/op\t       0 allocs/op",
            "extra": "4831904 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - ns/op",
            "value": 248.4,
            "unit": "ns/op",
            "extra": "4831904 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - B/op",
            "value": 121,
            "unit": "B/op",
            "extra": "4831904 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4831904 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc",
            "value": 255.5,
            "unit": "ns/op\t      16 B/op\t       2 allocs/op",
            "extra": "4701645 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - ns/op",
            "value": 255.5,
            "unit": "ns/op",
            "extra": "4701645 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - B/op",
            "value": 16,
            "unit": "B/op",
            "extra": "4701645 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - allocs/op",
            "value": 2,
            "unit": "allocs/op",
            "extra": "4701645 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint",
            "value": 1383,
            "unit": "ns/op\t      1000 datapoints\t     183 B/op\t       0 allocs/op",
            "extra": "871078 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - ns/op",
            "value": 1383,
            "unit": "ns/op",
            "extra": "871078 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - datapoints",
            "value": 1000,
            "unit": "datapoints",
            "extra": "871078 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - B/op",
            "value": 183,
            "unit": "B/op",
            "extra": "871078 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "871078 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation",
            "value": 220.7,
            "unit": "ns/op\t     126 B/op\t       0 allocs/op",
            "extra": "5400610 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - ns/op",
            "value": 220.7,
            "unit": "ns/op",
            "extra": "5400610 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - B/op",
            "value": 126,
            "unit": "B/op",
            "extra": "5400610 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "5400610 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData",
            "value": 248135,
            "unit": "ns/op\t  106803 B/op\t      13 allocs/op",
            "extra": "4580 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - ns/op",
            "value": 248135,
            "unit": "ns/op",
            "extra": "4580 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - B/op",
            "value": 106803,
            "unit": "B/op",
            "extra": "4580 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - allocs/op",
            "value": 13,
            "unit": "allocs/op",
            "extra": "4580 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small",
            "value": 21769,
            "unit": "ns/op\t     726 B/op\t      59 allocs/op",
            "extra": "53191 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - ns/op",
            "value": 21769,
            "unit": "ns/op",
            "extra": "53191 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - B/op",
            "value": 726,
            "unit": "B/op",
            "extra": "53191 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53191 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium",
            "value": 22255,
            "unit": "ns/op\t     728 B/op\t      59 allocs/op",
            "extra": "54739 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - ns/op",
            "value": 22255,
            "unit": "ns/op",
            "extra": "54739 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - B/op",
            "value": 728,
            "unit": "B/op",
            "extra": "54739 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54739 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large",
            "value": 21939,
            "unit": "ns/op\t     729 B/op\t      59 allocs/op",
            "extra": "54829 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - ns/op",
            "value": 21939,
            "unit": "ns/op",
            "extra": "54829 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - B/op",
            "value": 729,
            "unit": "B/op",
            "extra": "54829 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54829 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small",
            "value": 22031,
            "unit": "ns/op\t     702 B/op\t      60 allocs/op",
            "extra": "52653 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - ns/op",
            "value": 22031,
            "unit": "ns/op",
            "extra": "52653 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - B/op",
            "value": 702,
            "unit": "B/op",
            "extra": "52653 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52653 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium",
            "value": 22035,
            "unit": "ns/op\t     702 B/op\t      60 allocs/op",
            "extra": "54123 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - ns/op",
            "value": 22035,
            "unit": "ns/op",
            "extra": "54123 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - B/op",
            "value": 702,
            "unit": "B/op",
            "extra": "54123 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "54123 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large",
            "value": 22120,
            "unit": "ns/op\t     706 B/op\t      60 allocs/op",
            "extra": "53287 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - ns/op",
            "value": 22120,
            "unit": "ns/op",
            "extra": "53287 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - B/op",
            "value": 706,
            "unit": "B/op",
            "extra": "53287 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53287 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small",
            "value": 22564,
            "unit": "ns/op\t     701 B/op\t      60 allocs/op",
            "extra": "54012 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - ns/op",
            "value": 22564,
            "unit": "ns/op",
            "extra": "54012 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - B/op",
            "value": 701,
            "unit": "B/op",
            "extra": "54012 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "54012 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium",
            "value": 22577,
            "unit": "ns/op\t     702 B/op\t      60 allocs/op",
            "extra": "53835 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - ns/op",
            "value": 22577,
            "unit": "ns/op",
            "extra": "53835 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - B/op",
            "value": 702,
            "unit": "B/op",
            "extra": "53835 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53835 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large",
            "value": 22452,
            "unit": "ns/op\t     703 B/op\t      60 allocs/op",
            "extra": "54228 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - ns/op",
            "value": 22452,
            "unit": "ns/op",
            "extra": "54228 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - B/op",
            "value": 703,
            "unit": "B/op",
            "extra": "54228 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "54228 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small",
            "value": 20167,
            "unit": "ns/op\t     534 B/op\t      57 allocs/op",
            "extra": "59174 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - ns/op",
            "value": 20167,
            "unit": "ns/op",
            "extra": "59174 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - B/op",
            "value": 534,
            "unit": "B/op",
            "extra": "59174 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59174 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium",
            "value": 20288,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "60500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - ns/op",
            "value": 20288,
            "unit": "ns/op",
            "extra": "60500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "60500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60500 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large",
            "value": 20612,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "56704 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - ns/op",
            "value": 20612,
            "unit": "ns/op",
            "extra": "56704 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "56704 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "56704 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small",
            "value": 20582,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "58606 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - ns/op",
            "value": 20582,
            "unit": "ns/op",
            "extra": "58606 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "58606 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58606 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium",
            "value": 20698,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "58714 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - ns/op",
            "value": 20698,
            "unit": "ns/op",
            "extra": "58714 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "58714 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58714 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large",
            "value": 20436,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58392 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - ns/op",
            "value": 20436,
            "unit": "ns/op",
            "extra": "58392 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58392 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58392 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small",
            "value": 20242,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "57344 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - ns/op",
            "value": 20242,
            "unit": "ns/op",
            "extra": "57344 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "57344 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57344 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium",
            "value": 20276,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "57619 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - ns/op",
            "value": 20276,
            "unit": "ns/op",
            "extra": "57619 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "57619 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57619 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large",
            "value": 20350,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "57859 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - ns/op",
            "value": 20350,
            "unit": "ns/op",
            "extra": "57859 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "57859 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57859 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small",
            "value": 20082,
            "unit": "ns/op\t     534 B/op\t      57 allocs/op",
            "extra": "61010 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - ns/op",
            "value": 20082,
            "unit": "ns/op",
            "extra": "61010 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - B/op",
            "value": 534,
            "unit": "B/op",
            "extra": "61010 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "61010 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium",
            "value": 19462,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "60655 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - ns/op",
            "value": 19462,
            "unit": "ns/op",
            "extra": "60655 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "60655 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60655 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large",
            "value": 19633,
            "unit": "ns/op\t     534 B/op\t      57 allocs/op",
            "extra": "58862 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - ns/op",
            "value": 19633,
            "unit": "ns/op",
            "extra": "58862 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - B/op",
            "value": 534,
            "unit": "B/op",
            "extra": "58862 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58862 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small",
            "value": 20732,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "59088 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - ns/op",
            "value": 20732,
            "unit": "ns/op",
            "extra": "59088 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "59088 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "59088 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium",
            "value": 20601,
            "unit": "ns/op\t     539 B/op\t      58 allocs/op",
            "extra": "59119 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - ns/op",
            "value": 20601,
            "unit": "ns/op",
            "extra": "59119 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - B/op",
            "value": 539,
            "unit": "B/op",
            "extra": "59119 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "59119 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large",
            "value": 20477,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "57310 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - ns/op",
            "value": 20477,
            "unit": "ns/op",
            "extra": "57310 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "57310 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57310 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small",
            "value": 20192,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "57938 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - ns/op",
            "value": 20192,
            "unit": "ns/op",
            "extra": "57938 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "57938 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57938 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium",
            "value": 20132,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "58005 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - ns/op",
            "value": 20132,
            "unit": "ns/op",
            "extra": "58005 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "58005 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58005 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large",
            "value": 20499,
            "unit": "ns/op\t     544 B/op\t      58 allocs/op",
            "extra": "57810 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - ns/op",
            "value": 20499,
            "unit": "ns/op",
            "extra": "57810 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - B/op",
            "value": 544,
            "unit": "B/op",
            "extra": "57810 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57810 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration",
            "value": 5.628,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "213262339 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - ns/op",
            "value": 5.628,
            "unit": "ns/op",
            "extra": "213262339 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "213262339 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "213262339 times\n4 procs"
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
            "value": 0.0000108,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling - ns/op",
            "value": 0.0000108,
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
            "value": 40149,
            "unit": "ns/op\t    1365 B/op\t     114 allocs/op",
            "extra": "30073 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - ns/op",
            "value": 40149,
            "unit": "ns/op",
            "extra": "30073 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - B/op",
            "value": 1365,
            "unit": "B/op",
            "extra": "30073 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30073 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4",
            "value": 39946,
            "unit": "ns/op\t    1364 B/op\t     114 allocs/op",
            "extra": "30036 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - ns/op",
            "value": 39946,
            "unit": "ns/op",
            "extra": "30036 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - B/op",
            "value": 1364,
            "unit": "B/op",
            "extra": "30036 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30036 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8",
            "value": 39897,
            "unit": "ns/op\t    1363 B/op\t     114 allocs/op",
            "extra": "30012 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - ns/op",
            "value": 39897,
            "unit": "ns/op",
            "extra": "30012 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - B/op",
            "value": 1363,
            "unit": "B/op",
            "extra": "30012 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30012 times\n4 procs"
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
            "value": 22057,
            "unit": "ns/op\t   53151 B/op\t      37 allocs/op",
            "extra": "55184 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - ns/op",
            "value": 22057,
            "unit": "ns/op",
            "extra": "55184 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - B/op",
            "value": 53151,
            "unit": "B/op",
            "extra": "55184 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "55184 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation",
            "value": 55.42,
            "unit": "ns/op\t        32.00 bytes/point\t       0 B/op\t       0 allocs/op",
            "extra": "21526768 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - ns/op",
            "value": 55.42,
            "unit": "ns/op",
            "extra": "21526768 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - bytes/point",
            "value": 32,
            "unit": "bytes/point",
            "extra": "21526768 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21526768 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21526768 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData",
            "value": 259832,
            "unit": "ns/op\t  123584 B/op\t      19 allocs/op",
            "extra": "4332 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - ns/op",
            "value": 259832,
            "unit": "ns/op",
            "extra": "4332 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - B/op",
            "value": 123584,
            "unit": "B/op",
            "extra": "4332 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - allocs/op",
            "value": 19,
            "unit": "allocs/op",
            "extra": "4332 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing",
            "value": 5638,
            "unit": "ns/op\t 211786000 packets/op\t       0 B/op\t       0 allocs/op",
            "extra": "211786 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - ns/op",
            "value": 5638,
            "unit": "ns/op",
            "extra": "211786 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - packets/op",
            "value": 211786000,
            "unit": "packets/op",
            "extra": "211786 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "211786 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "211786 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit",
            "value": 2.53,
            "unit": "ns/op\t       100.0 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "480131866 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - ns/op",
            "value": 2.53,
            "unit": "ns/op",
            "extra": "480131866 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allowed%",
            "value": 100,
            "unit": "allowed%",
            "extra": "480131866 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "480131866 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "480131866 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS",
            "value": 117.9,
            "unit": "ns/op\t         0.1278 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10169830 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - ns/op",
            "value": 117.9,
            "unit": "ns/op",
            "extra": "10169830 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allowed%",
            "value": 0.1278,
            "unit": "allowed%",
            "extra": "10169830 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10169830 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10169830 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS",
            "value": 118.3,
            "unit": "ns/op\t         1.281 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10165801 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - ns/op",
            "value": 118.3,
            "unit": "ns/op",
            "extra": "10165801 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allowed%",
            "value": 1.281,
            "unit": "allowed%",
            "extra": "10165801 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10165801 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10165801 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS",
            "value": 118.7,
            "unit": "ns/op\t        12.85 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10203499 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - ns/op",
            "value": 118.7,
            "unit": "ns/op",
            "extra": "10203499 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allowed%",
            "value": 12.85,
            "unit": "allowed%",
            "extra": "10203499 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10203499 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10203499 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool",
            "value": 326,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "3664598 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - ns/op",
            "value": 326,
            "unit": "ns/op",
            "extra": "3664598 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "3664598 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "3664598 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool",
            "value": 2437,
            "unit": "ns/op\t   14560 B/op\t       1 allocs/op",
            "extra": "473217 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - ns/op",
            "value": 2437,
            "unit": "ns/op",
            "extra": "473217 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - B/op",
            "value": 14560,
            "unit": "B/op",
            "extra": "473217 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "473217 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController",
            "value": 355.2,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3513374 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - ns/op",
            "value": 355.2,
            "unit": "ns/op",
            "extra": "3513374 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3513374 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3513374 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64",
            "value": 5.299,
            "unit": "ns/op\t12077.62 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226726644 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - ns/op",
            "value": 5.299,
            "unit": "ns/op",
            "extra": "226726644 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - MB/s",
            "value": 12077.62,
            "unit": "MB/s",
            "extra": "226726644 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226726644 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226726644 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256",
            "value": 5.303,
            "unit": "ns/op\t48271.80 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226182855 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - ns/op",
            "value": 5.303,
            "unit": "ns/op",
            "extra": "226182855 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - MB/s",
            "value": 48271.8,
            "unit": "MB/s",
            "extra": "226182855 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226182855 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226182855 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512",
            "value": 5.303,
            "unit": "ns/op\t96544.16 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226245538 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - ns/op",
            "value": 5.303,
            "unit": "ns/op",
            "extra": "226245538 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - MB/s",
            "value": 96544.16,
            "unit": "MB/s",
            "extra": "226245538 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226245538 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226245538 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024",
            "value": 5.299,
            "unit": "ns/op\t193254.41 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226667792 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - ns/op",
            "value": 5.299,
            "unit": "ns/op",
            "extra": "226667792 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - MB/s",
            "value": 193254.41,
            "unit": "MB/s",
            "extra": "226667792 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226667792 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226667792 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500",
            "value": 5.371,
            "unit": "ns/op\t279282.10 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226291104 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - ns/op",
            "value": 5.371,
            "unit": "ns/op",
            "extra": "226291104 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - MB/s",
            "value": 279282.1,
            "unit": "MB/s",
            "extra": "226291104 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226291104 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226291104 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000",
            "value": 5.294,
            "unit": "ns/op\t1699973.40 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226204730 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - ns/op",
            "value": 5.294,
            "unit": "ns/op",
            "extra": "226204730 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - MB/s",
            "value": 1699973.4,
            "unit": "MB/s",
            "extra": "226204730 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226204730 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226204730 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline",
            "value": 54788,
            "unit": "ns/op\t         0 MB/op\t       0 B/op\t       0 allocs/op",
            "extra": "21777 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - ns/op",
            "value": 54788,
            "unit": "ns/op",
            "extra": "21777 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - MB/op",
            "value": 0,
            "unit": "MB/op",
            "extra": "21777 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21777 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21777 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple",
            "value": 91.17,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "13103947 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - ns/op",
            "value": 91.17,
            "unit": "ns/op",
            "extra": "13103947 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "13103947 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "13103947 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID",
            "value": 273.4,
            "unit": "ns/op\t      61 B/op\t       3 allocs/op",
            "extra": "4373126 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - ns/op",
            "value": 273.4,
            "unit": "ns/op",
            "extra": "4373126 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - B/op",
            "value": 61,
            "unit": "B/op",
            "extra": "4373126 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "4373126 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket",
            "value": 270.6,
            "unit": "ns/op\t    3429 B/op\t       0 allocs/op",
            "extra": "4941544 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - ns/op",
            "value": 270.6,
            "unit": "ns/op",
            "extra": "4941544 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - B/op",
            "value": 3429,
            "unit": "B/op",
            "extra": "4941544 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4941544 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small",
            "value": 22491,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "53722 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - ns/op",
            "value": 22491,
            "unit": "ns/op",
            "extra": "53722 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "53722 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53722 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium",
            "value": 22188,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "53762 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - ns/op",
            "value": 22188,
            "unit": "ns/op",
            "extra": "53762 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "53762 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53762 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large",
            "value": 22207,
            "unit": "ns/op\t     723 B/op\t      59 allocs/op",
            "extra": "53203 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - ns/op",
            "value": 22207,
            "unit": "ns/op",
            "extra": "53203 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - B/op",
            "value": 723,
            "unit": "B/op",
            "extra": "53203 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53203 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small",
            "value": 20312,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "58564 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - ns/op",
            "value": 20312,
            "unit": "ns/op",
            "extra": "58564 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "58564 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58564 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium",
            "value": 20321,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "59300 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - ns/op",
            "value": 20321,
            "unit": "ns/op",
            "extra": "59300 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "59300 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59300 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large",
            "value": 20275,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "58638 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - ns/op",
            "value": 20275,
            "unit": "ns/op",
            "extra": "58638 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "58638 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58638 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small",
            "value": 20042,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "59404 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - ns/op",
            "value": 20042,
            "unit": "ns/op",
            "extra": "59404 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "59404 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59404 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium",
            "value": 20127,
            "unit": "ns/op\t     529 B/op\t      57 allocs/op",
            "extra": "59438 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - ns/op",
            "value": 20127,
            "unit": "ns/op",
            "extra": "59438 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - B/op",
            "value": 529,
            "unit": "B/op",
            "extra": "59438 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59438 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large",
            "value": 20144,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "58539 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - ns/op",
            "value": 20144,
            "unit": "ns/op",
            "extra": "58539 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "58539 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58539 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix",
            "value": 44845,
            "unit": "ns/op\t   28955 B/op\t     362 allocs/op",
            "extra": "29286 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - ns/op",
            "value": 44845,
            "unit": "ns/op",
            "extra": "29286 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - B/op",
            "value": 28955,
            "unit": "B/op",
            "extra": "29286 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - allocs/op",
            "value": 362,
            "unit": "allocs/op",
            "extra": "29286 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap",
            "value": 6478,
            "unit": "ns/op\t    3696 B/op\t      52 allocs/op",
            "extra": "185878 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - ns/op",
            "value": 6478,
            "unit": "ns/op",
            "extra": "185878 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - B/op",
            "value": 3696,
            "unit": "B/op",
            "extra": "185878 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - allocs/op",
            "value": 52,
            "unit": "allocs/op",
            "extra": "185878 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer",
            "value": 9585,
            "unit": "ns/op\t    7257 B/op\t      34 allocs/op",
            "extra": "123423 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - ns/op",
            "value": 9585,
            "unit": "ns/op",
            "extra": "123423 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - B/op",
            "value": 7257,
            "unit": "B/op",
            "extra": "123423 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - allocs/op",
            "value": 34,
            "unit": "allocs/op",
            "extra": "123423 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey",
            "value": 2382,
            "unit": "ns/op\t    1400 B/op\t      27 allocs/op",
            "extra": "485322 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - ns/op",
            "value": 2382,
            "unit": "ns/op",
            "extra": "485322 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - B/op",
            "value": 1400,
            "unit": "B/op",
            "extra": "485322 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "485322 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial",
            "value": 16618,
            "unit": "ns/op\t   16466 B/op\t      98 allocs/op",
            "extra": "72088 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - ns/op",
            "value": 16618,
            "unit": "ns/op",
            "extra": "72088 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - B/op",
            "value": 16466,
            "unit": "B/op",
            "extra": "72088 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - allocs/op",
            "value": 98,
            "unit": "allocs/op",
            "extra": "72088 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor",
            "value": 8.805,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "136829428 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - ns/op",
            "value": 8.805,
            "unit": "ns/op",
            "extra": "136829428 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "136829428 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "136829428 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor",
            "value": 24.15,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "49667872 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - ns/op",
            "value": 24.15,
            "unit": "ns/op",
            "extra": "49667872 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "49667872 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "49667872 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex",
            "value": 36.41,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "31108368 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - ns/op",
            "value": 36.41,
            "unit": "ns/op",
            "extra": "31108368 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "31108368 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "31108368 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow",
            "value": 6.551,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "183255169 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - ns/op",
            "value": 6.551,
            "unit": "ns/op",
            "extra": "183255169 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "183255169 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "183255169 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse",
            "value": 18.57,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "64543171 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - ns/op",
            "value": 18.57,
            "unit": "ns/op",
            "extra": "64543171 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "64543171 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "64543171 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire",
            "value": 5.926,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "202592791 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - ns/op",
            "value": 5.926,
            "unit": "ns/op",
            "extra": "202592791 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "202592791 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "202592791 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix",
            "value": 3.746,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "320336545 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - ns/op",
            "value": 3.746,
            "unit": "ns/op",
            "extra": "320336545 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "320336545 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "320336545 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave",
            "value": 33.09,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "36911910 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - ns/op",
            "value": 33.09,
            "unit": "ns/op",
            "extra": "36911910 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "36911910 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "36911910 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle",
            "value": 3.781,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "321129094 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - ns/op",
            "value": 3.781,
            "unit": "ns/op",
            "extra": "321129094 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "321129094 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "321129094 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10",
            "value": 103559,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10 - ns/op",
            "value": 103559,
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
            "value": 104102,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - ns/op",
            "value": 104102,
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
            "value": 103803,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000 - ns/op",
            "value": 103803,
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
            "value": 447.8,
            "unit": "ns/op\t     229 B/op\t       3 allocs/op",
            "extra": "2664781 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - ns/op",
            "value": 447.8,
            "unit": "ns/op",
            "extra": "2664781 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - B/op",
            "value": 229,
            "unit": "B/op",
            "extra": "2664781 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2664781 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2",
            "value": 9014,
            "unit": "ns/op\t   17464 B/op\t      77 allocs/op",
            "extra": "128589 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - ns/op",
            "value": 9014,
            "unit": "ns/op",
            "extra": "128589 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - B/op",
            "value": 17464,
            "unit": "B/op",
            "extra": "128589 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - allocs/op",
            "value": 77,
            "unit": "allocs/op",
            "extra": "128589 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3",
            "value": 24837,
            "unit": "ns/op\t   47576 B/op\t     200 allocs/op",
            "extra": "47589 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - ns/op",
            "value": 24837,
            "unit": "ns/op",
            "extra": "47589 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - B/op",
            "value": 47576,
            "unit": "B/op",
            "extra": "47589 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - allocs/op",
            "value": 200,
            "unit": "allocs/op",
            "extra": "47589 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4",
            "value": 35782,
            "unit": "ns/op\t   69816 B/op\t     295 allocs/op",
            "extra": "33465 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - ns/op",
            "value": 35782,
            "unit": "ns/op",
            "extra": "33465 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - B/op",
            "value": 69816,
            "unit": "B/op",
            "extra": "33465 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - allocs/op",
            "value": 295,
            "unit": "allocs/op",
            "extra": "33465 times\n4 procs"
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
          "id": "98fa60d77c7e6116adc121fc2aab4736a364ab31",
          "message": "ci: update release workflows to Go 1.24 and replace deprecated macos-13",
          "timestamp": "2026-02-18T13:09:32Z",
          "url": "https://github.com/perplext/nsd/pull/50/commits/98fa60d77c7e6116adc121fc2aab4736a364ab31"
        },
        "date": 1771421172396,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkProcessTLSPacket",
            "value": 621.7,
            "unit": "ns/op\t     208 B/op\t       8 allocs/op",
            "extra": "1958989 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - ns/op",
            "value": 621.7,
            "unit": "ns/op",
            "extra": "1958989 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - B/op",
            "value": 208,
            "unit": "B/op",
            "extra": "1958989 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1958989 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes",
            "value": 7054,
            "unit": "ns/op\t    1588 B/op\t      93 allocs/op",
            "extra": "165008 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - ns/op",
            "value": 7054,
            "unit": "ns/op",
            "extra": "165008 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - B/op",
            "value": 1588,
            "unit": "B/op",
            "extra": "165008 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - allocs/op",
            "value": 93,
            "unit": "allocs/op",
            "extra": "165008 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint",
            "value": 161.1,
            "unit": "ns/op\t      60 B/op\t       0 allocs/op",
            "extra": "7391167 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - ns/op",
            "value": 161.1,
            "unit": "ns/op",
            "extra": "7391167 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - B/op",
            "value": 60,
            "unit": "B/op",
            "extra": "7391167 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "7391167 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint",
            "value": 249.4,
            "unit": "ns/op\t     121 B/op\t       0 allocs/op",
            "extra": "4823310 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - ns/op",
            "value": 249.4,
            "unit": "ns/op",
            "extra": "4823310 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - B/op",
            "value": 121,
            "unit": "B/op",
            "extra": "4823310 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4823310 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc",
            "value": 251.8,
            "unit": "ns/op\t      16 B/op\t       2 allocs/op",
            "extra": "4761813 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - ns/op",
            "value": 251.8,
            "unit": "ns/op",
            "extra": "4761813 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - B/op",
            "value": 16,
            "unit": "B/op",
            "extra": "4761813 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - allocs/op",
            "value": 2,
            "unit": "allocs/op",
            "extra": "4761813 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint",
            "value": 1375,
            "unit": "ns/op\t      1000 datapoints\t     183 B/op\t       0 allocs/op",
            "extra": "879814 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - ns/op",
            "value": 1375,
            "unit": "ns/op",
            "extra": "879814 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - datapoints",
            "value": 1000,
            "unit": "datapoints",
            "extra": "879814 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - B/op",
            "value": 183,
            "unit": "B/op",
            "extra": "879814 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "879814 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation",
            "value": 221.2,
            "unit": "ns/op\t     126 B/op\t       0 allocs/op",
            "extra": "5404632 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - ns/op",
            "value": 221.2,
            "unit": "ns/op",
            "extra": "5404632 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - B/op",
            "value": 126,
            "unit": "B/op",
            "extra": "5404632 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "5404632 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData",
            "value": 246873,
            "unit": "ns/op\t  106801 B/op\t      13 allocs/op",
            "extra": "4862 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - ns/op",
            "value": 246873,
            "unit": "ns/op",
            "extra": "4862 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - B/op",
            "value": 106801,
            "unit": "B/op",
            "extra": "4862 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - allocs/op",
            "value": 13,
            "unit": "allocs/op",
            "extra": "4862 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small",
            "value": 22002,
            "unit": "ns/op\t     727 B/op\t      59 allocs/op",
            "extra": "53676 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - ns/op",
            "value": 22002,
            "unit": "ns/op",
            "extra": "53676 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - B/op",
            "value": 727,
            "unit": "B/op",
            "extra": "53676 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53676 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium",
            "value": 22207,
            "unit": "ns/op\t     727 B/op\t      59 allocs/op",
            "extra": "54346 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - ns/op",
            "value": 22207,
            "unit": "ns/op",
            "extra": "54346 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - B/op",
            "value": 727,
            "unit": "B/op",
            "extra": "54346 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54346 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large",
            "value": 22217,
            "unit": "ns/op\t     727 B/op\t      59 allocs/op",
            "extra": "54162 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - ns/op",
            "value": 22217,
            "unit": "ns/op",
            "extra": "54162 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - B/op",
            "value": 727,
            "unit": "B/op",
            "extra": "54162 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54162 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small",
            "value": 22438,
            "unit": "ns/op\t     703 B/op\t      60 allocs/op",
            "extra": "51770 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - ns/op",
            "value": 22438,
            "unit": "ns/op",
            "extra": "51770 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - B/op",
            "value": 703,
            "unit": "B/op",
            "extra": "51770 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "51770 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium",
            "value": 22139,
            "unit": "ns/op\t     702 B/op\t      60 allocs/op",
            "extra": "53888 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - ns/op",
            "value": 22139,
            "unit": "ns/op",
            "extra": "53888 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - B/op",
            "value": 702,
            "unit": "B/op",
            "extra": "53888 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53888 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large",
            "value": 22456,
            "unit": "ns/op\t     706 B/op\t      60 allocs/op",
            "extra": "53553 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - ns/op",
            "value": 22456,
            "unit": "ns/op",
            "extra": "53553 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - B/op",
            "value": 706,
            "unit": "B/op",
            "extra": "53553 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53553 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small",
            "value": 22538,
            "unit": "ns/op\t     706 B/op\t      60 allocs/op",
            "extra": "53414 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - ns/op",
            "value": 22538,
            "unit": "ns/op",
            "extra": "53414 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - B/op",
            "value": 706,
            "unit": "B/op",
            "extra": "53414 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53414 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium",
            "value": 22435,
            "unit": "ns/op\t     703 B/op\t      60 allocs/op",
            "extra": "53984 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - ns/op",
            "value": 22435,
            "unit": "ns/op",
            "extra": "53984 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - B/op",
            "value": 703,
            "unit": "B/op",
            "extra": "53984 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53984 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large",
            "value": 22483,
            "unit": "ns/op\t     707 B/op\t      60 allocs/op",
            "extra": "54087 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - ns/op",
            "value": 22483,
            "unit": "ns/op",
            "extra": "54087 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - B/op",
            "value": 707,
            "unit": "B/op",
            "extra": "54087 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "54087 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small",
            "value": 19807,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "59566 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - ns/op",
            "value": 19807,
            "unit": "ns/op",
            "extra": "59566 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "59566 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59566 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium",
            "value": 20072,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "58962 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - ns/op",
            "value": 20072,
            "unit": "ns/op",
            "extra": "58962 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "58962 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58962 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large",
            "value": 19853,
            "unit": "ns/op\t     535 B/op\t      57 allocs/op",
            "extra": "58935 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - ns/op",
            "value": 19853,
            "unit": "ns/op",
            "extra": "58935 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - B/op",
            "value": 535,
            "unit": "B/op",
            "extra": "58935 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58935 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small",
            "value": 20437,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "57736 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - ns/op",
            "value": 20437,
            "unit": "ns/op",
            "extra": "57736 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "57736 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57736 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium",
            "value": 20286,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "57820 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - ns/op",
            "value": 20286,
            "unit": "ns/op",
            "extra": "57820 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "57820 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57820 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large",
            "value": 20412,
            "unit": "ns/op\t     544 B/op\t      58 allocs/op",
            "extra": "57099 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - ns/op",
            "value": 20412,
            "unit": "ns/op",
            "extra": "57099 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - B/op",
            "value": 544,
            "unit": "B/op",
            "extra": "57099 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57099 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small",
            "value": 20417,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "57681 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - ns/op",
            "value": 20417,
            "unit": "ns/op",
            "extra": "57681 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "57681 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57681 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium",
            "value": 20277,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "57865 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - ns/op",
            "value": 20277,
            "unit": "ns/op",
            "extra": "57865 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "57865 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57865 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large",
            "value": 20399,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "57854 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - ns/op",
            "value": 20399,
            "unit": "ns/op",
            "extra": "57854 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "57854 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57854 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small",
            "value": 19754,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "56905 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - ns/op",
            "value": 19754,
            "unit": "ns/op",
            "extra": "56905 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "56905 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "56905 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium",
            "value": 19685,
            "unit": "ns/op\t     534 B/op\t      57 allocs/op",
            "extra": "59865 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - ns/op",
            "value": 19685,
            "unit": "ns/op",
            "extra": "59865 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - B/op",
            "value": 534,
            "unit": "B/op",
            "extra": "59865 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59865 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large",
            "value": 19690,
            "unit": "ns/op\t     537 B/op\t      57 allocs/op",
            "extra": "59679 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - ns/op",
            "value": 19690,
            "unit": "ns/op",
            "extra": "59679 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - B/op",
            "value": 537,
            "unit": "B/op",
            "extra": "59679 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59679 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small",
            "value": 20610,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "58599 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - ns/op",
            "value": 20610,
            "unit": "ns/op",
            "extra": "58599 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "58599 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58599 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium",
            "value": 20365,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "59161 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - ns/op",
            "value": 20365,
            "unit": "ns/op",
            "extra": "59161 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "59161 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "59161 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large",
            "value": 20276,
            "unit": "ns/op\t     544 B/op\t      58 allocs/op",
            "extra": "57700 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - ns/op",
            "value": 20276,
            "unit": "ns/op",
            "extra": "57700 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - B/op",
            "value": 544,
            "unit": "B/op",
            "extra": "57700 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57700 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small",
            "value": 20178,
            "unit": "ns/op\t     540 B/op\t      58 allocs/op",
            "extra": "57850 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - ns/op",
            "value": 20178,
            "unit": "ns/op",
            "extra": "57850 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - B/op",
            "value": 540,
            "unit": "B/op",
            "extra": "57850 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57850 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium",
            "value": 20167,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "58101 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - ns/op",
            "value": 20167,
            "unit": "ns/op",
            "extra": "58101 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "58101 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58101 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large",
            "value": 20893,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "58088 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - ns/op",
            "value": 20893,
            "unit": "ns/op",
            "extra": "58088 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "58088 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58088 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration",
            "value": 5.703,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "210800055 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - ns/op",
            "value": 5.703,
            "unit": "ns/op",
            "extra": "210800055 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "210800055 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "210800055 times\n4 procs"
          },
          {
            "name": "BenchmarkInterpolation",
            "value": 2e-7,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkInterpolation - ns/op",
            "value": 2e-7,
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
            "value": 0.0000183,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling - ns/op",
            "value": 0.0000183,
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
            "value": 39658,
            "unit": "ns/op\t    1363 B/op\t     114 allocs/op",
            "extra": "30080 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - ns/op",
            "value": 39658,
            "unit": "ns/op",
            "extra": "30080 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - B/op",
            "value": 1363,
            "unit": "B/op",
            "extra": "30080 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30080 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4",
            "value": 39739,
            "unit": "ns/op\t    1363 B/op\t     114 allocs/op",
            "extra": "30126 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - ns/op",
            "value": 39739,
            "unit": "ns/op",
            "extra": "30126 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - B/op",
            "value": 1363,
            "unit": "B/op",
            "extra": "30126 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30126 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8",
            "value": 39783,
            "unit": "ns/op\t    1360 B/op\t     114 allocs/op",
            "extra": "30103 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - ns/op",
            "value": 39783,
            "unit": "ns/op",
            "extra": "30103 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - B/op",
            "value": 1360,
            "unit": "B/op",
            "extra": "30103 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30103 times\n4 procs"
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
            "value": 4e-7,
            "unit": "ns/op\t      3610 datapoints\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s - ns/op",
            "value": 4e-7,
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
            "value": 21024,
            "unit": "ns/op\t   53126 B/op\t      37 allocs/op",
            "extra": "56538 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - ns/op",
            "value": 21024,
            "unit": "ns/op",
            "extra": "56538 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - B/op",
            "value": 53126,
            "unit": "B/op",
            "extra": "56538 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "56538 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation",
            "value": 55.42,
            "unit": "ns/op\t        32.00 bytes/point\t       0 B/op\t       0 allocs/op",
            "extra": "21616882 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - ns/op",
            "value": 55.42,
            "unit": "ns/op",
            "extra": "21616882 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - bytes/point",
            "value": 32,
            "unit": "bytes/point",
            "extra": "21616882 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21616882 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21616882 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData",
            "value": 258560,
            "unit": "ns/op\t  123584 B/op\t      19 allocs/op",
            "extra": "4399 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - ns/op",
            "value": 258560,
            "unit": "ns/op",
            "extra": "4399 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - B/op",
            "value": 123584,
            "unit": "B/op",
            "extra": "4399 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - allocs/op",
            "value": 19,
            "unit": "allocs/op",
            "extra": "4399 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing",
            "value": 5620,
            "unit": "ns/op\t 212082000 packets/op\t       0 B/op\t       0 allocs/op",
            "extra": "212082 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - ns/op",
            "value": 5620,
            "unit": "ns/op",
            "extra": "212082 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - packets/op",
            "value": 212082000,
            "unit": "packets/op",
            "extra": "212082 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "212082 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "212082 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit",
            "value": 2.505,
            "unit": "ns/op\t       100.0 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "480866808 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - ns/op",
            "value": 2.505,
            "unit": "ns/op",
            "extra": "480866808 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allowed%",
            "value": 100,
            "unit": "allowed%",
            "extra": "480866808 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "480866808 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "480866808 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS",
            "value": 121.9,
            "unit": "ns/op\t         0.1317 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10142488 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - ns/op",
            "value": 121.9,
            "unit": "ns/op",
            "extra": "10142488 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allowed%",
            "value": 0.1317,
            "unit": "allowed%",
            "extra": "10142488 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10142488 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10142488 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS",
            "value": 117.9,
            "unit": "ns/op\t         1.278 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10186797 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - ns/op",
            "value": 117.9,
            "unit": "ns/op",
            "extra": "10186797 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allowed%",
            "value": 1.278,
            "unit": "allowed%",
            "extra": "10186797 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10186797 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10186797 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS",
            "value": 118.6,
            "unit": "ns/op\t        12.84 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10219110 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - ns/op",
            "value": 118.6,
            "unit": "ns/op",
            "extra": "10219110 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allowed%",
            "value": 12.84,
            "unit": "allowed%",
            "extra": "10219110 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10219110 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10219110 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool",
            "value": 325,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "3690958 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - ns/op",
            "value": 325,
            "unit": "ns/op",
            "extra": "3690958 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "3690958 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "3690958 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool",
            "value": 2524,
            "unit": "ns/op\t   14560 B/op\t       1 allocs/op",
            "extra": "429085 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - ns/op",
            "value": 2524,
            "unit": "ns/op",
            "extra": "429085 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - B/op",
            "value": 14560,
            "unit": "B/op",
            "extra": "429085 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "429085 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController",
            "value": 336.3,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3557707 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - ns/op",
            "value": 336.3,
            "unit": "ns/op",
            "extra": "3557707 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3557707 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3557707 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64",
            "value": 5.33,
            "unit": "ns/op\t12008.61 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226468690 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - ns/op",
            "value": 5.33,
            "unit": "ns/op",
            "extra": "226468690 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - MB/s",
            "value": 12008.61,
            "unit": "MB/s",
            "extra": "226468690 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226468690 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226468690 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256",
            "value": 5.301,
            "unit": "ns/op\t48291.05 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226557916 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - ns/op",
            "value": 5.301,
            "unit": "ns/op",
            "extra": "226557916 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - MB/s",
            "value": 48291.05,
            "unit": "MB/s",
            "extra": "226557916 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226557916 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226557916 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512",
            "value": 5.298,
            "unit": "ns/op\t96648.79 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226471153 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - ns/op",
            "value": 5.298,
            "unit": "ns/op",
            "extra": "226471153 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - MB/s",
            "value": 96648.79,
            "unit": "MB/s",
            "extra": "226471153 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226471153 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226471153 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024",
            "value": 5.299,
            "unit": "ns/op\t193232.65 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226689826 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - ns/op",
            "value": 5.299,
            "unit": "ns/op",
            "extra": "226689826 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - MB/s",
            "value": 193232.65,
            "unit": "MB/s",
            "extra": "226689826 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226689826 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226689826 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500",
            "value": 5.303,
            "unit": "ns/op\t282844.92 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226571157 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - ns/op",
            "value": 5.303,
            "unit": "ns/op",
            "extra": "226571157 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - MB/s",
            "value": 282844.92,
            "unit": "MB/s",
            "extra": "226571157 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226571157 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226571157 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000",
            "value": 5.301,
            "unit": "ns/op\t1697939.40 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226425534 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - ns/op",
            "value": 5.301,
            "unit": "ns/op",
            "extra": "226425534 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - MB/s",
            "value": 1697939.4,
            "unit": "MB/s",
            "extra": "226425534 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226425534 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226425534 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline",
            "value": 54709,
            "unit": "ns/op\t         0 MB/op\t       0 B/op\t       0 allocs/op",
            "extra": "21900 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - ns/op",
            "value": 54709,
            "unit": "ns/op",
            "extra": "21900 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - MB/op",
            "value": 0,
            "unit": "MB/op",
            "extra": "21900 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21900 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21900 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple",
            "value": 91.15,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "13320679 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - ns/op",
            "value": 91.15,
            "unit": "ns/op",
            "extra": "13320679 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "13320679 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "13320679 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID",
            "value": 278.6,
            "unit": "ns/op\t      61 B/op\t       3 allocs/op",
            "extra": "4263788 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - ns/op",
            "value": 278.6,
            "unit": "ns/op",
            "extra": "4263788 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - B/op",
            "value": 61,
            "unit": "B/op",
            "extra": "4263788 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "4263788 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket",
            "value": 264.9,
            "unit": "ns/op\t    3514 B/op\t       0 allocs/op",
            "extra": "4821721 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - ns/op",
            "value": 264.9,
            "unit": "ns/op",
            "extra": "4821721 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - B/op",
            "value": 3514,
            "unit": "B/op",
            "extra": "4821721 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4821721 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small",
            "value": 22246,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "53390 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - ns/op",
            "value": 22246,
            "unit": "ns/op",
            "extra": "53390 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "53390 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53390 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium",
            "value": 22335,
            "unit": "ns/op\t     727 B/op\t      59 allocs/op",
            "extra": "53347 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - ns/op",
            "value": 22335,
            "unit": "ns/op",
            "extra": "53347 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - B/op",
            "value": 727,
            "unit": "B/op",
            "extra": "53347 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53347 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large",
            "value": 22277,
            "unit": "ns/op\t     722 B/op\t      59 allocs/op",
            "extra": "53496 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - ns/op",
            "value": 22277,
            "unit": "ns/op",
            "extra": "53496 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - B/op",
            "value": 722,
            "unit": "B/op",
            "extra": "53496 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53496 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small",
            "value": 20452,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "59172 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - ns/op",
            "value": 20452,
            "unit": "ns/op",
            "extra": "59172 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "59172 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59172 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium",
            "value": 20294,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "59001 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - ns/op",
            "value": 20294,
            "unit": "ns/op",
            "extra": "59001 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "59001 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59001 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large",
            "value": 20389,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58426 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - ns/op",
            "value": 20389,
            "unit": "ns/op",
            "extra": "58426 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58426 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58426 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small",
            "value": 20107,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "58441 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - ns/op",
            "value": 20107,
            "unit": "ns/op",
            "extra": "58441 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "58441 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58441 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium",
            "value": 20115,
            "unit": "ns/op\t     531 B/op\t      57 allocs/op",
            "extra": "59121 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - ns/op",
            "value": 20115,
            "unit": "ns/op",
            "extra": "59121 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - B/op",
            "value": 531,
            "unit": "B/op",
            "extra": "59121 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59121 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large",
            "value": 20234,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58986 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - ns/op",
            "value": 20234,
            "unit": "ns/op",
            "extra": "58986 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58986 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58986 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix",
            "value": 42805,
            "unit": "ns/op\t   28459 B/op\t     331 allocs/op",
            "extra": "26312 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - ns/op",
            "value": 42805,
            "unit": "ns/op",
            "extra": "26312 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - B/op",
            "value": 28459,
            "unit": "B/op",
            "extra": "26312 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - allocs/op",
            "value": 331,
            "unit": "allocs/op",
            "extra": "26312 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap",
            "value": 6493,
            "unit": "ns/op\t    3696 B/op\t      52 allocs/op",
            "extra": "182817 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - ns/op",
            "value": 6493,
            "unit": "ns/op",
            "extra": "182817 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - B/op",
            "value": 3696,
            "unit": "B/op",
            "extra": "182817 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - allocs/op",
            "value": 52,
            "unit": "allocs/op",
            "extra": "182817 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer",
            "value": 9869,
            "unit": "ns/op\t    7257 B/op\t      34 allocs/op",
            "extra": "122257 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - ns/op",
            "value": 9869,
            "unit": "ns/op",
            "extra": "122257 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - B/op",
            "value": 7257,
            "unit": "B/op",
            "extra": "122257 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - allocs/op",
            "value": 34,
            "unit": "allocs/op",
            "extra": "122257 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey",
            "value": 2388,
            "unit": "ns/op\t    1400 B/op\t      27 allocs/op",
            "extra": "484366 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - ns/op",
            "value": 2388,
            "unit": "ns/op",
            "extra": "484366 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - B/op",
            "value": 1400,
            "unit": "B/op",
            "extra": "484366 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "484366 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial",
            "value": 16870,
            "unit": "ns/op\t   16466 B/op\t      98 allocs/op",
            "extra": "69172 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - ns/op",
            "value": 16870,
            "unit": "ns/op",
            "extra": "69172 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - B/op",
            "value": 16466,
            "unit": "B/op",
            "extra": "69172 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - allocs/op",
            "value": 98,
            "unit": "allocs/op",
            "extra": "69172 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor",
            "value": 8.728,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "137357878 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - ns/op",
            "value": 8.728,
            "unit": "ns/op",
            "extra": "137357878 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "137357878 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "137357878 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor",
            "value": 24.14,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "49767384 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - ns/op",
            "value": 24.14,
            "unit": "ns/op",
            "extra": "49767384 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "49767384 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "49767384 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex",
            "value": 36.22,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "33136483 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - ns/op",
            "value": 36.22,
            "unit": "ns/op",
            "extra": "33136483 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "33136483 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "33136483 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow",
            "value": 6.541,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "173720043 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - ns/op",
            "value": 6.541,
            "unit": "ns/op",
            "extra": "173720043 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "173720043 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "173720043 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse",
            "value": 18.52,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "64785990 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - ns/op",
            "value": 18.52,
            "unit": "ns/op",
            "extra": "64785990 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "64785990 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "64785990 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire",
            "value": 5.937,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "202658084 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - ns/op",
            "value": 5.937,
            "unit": "ns/op",
            "extra": "202658084 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "202658084 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "202658084 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix",
            "value": 3.748,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "320480779 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - ns/op",
            "value": 3.748,
            "unit": "ns/op",
            "extra": "320480779 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "320480779 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "320480779 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave",
            "value": 32.46,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "37142892 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - ns/op",
            "value": 32.46,
            "unit": "ns/op",
            "extra": "37142892 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "37142892 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "37142892 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle",
            "value": 3.746,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "320632473 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - ns/op",
            "value": 3.746,
            "unit": "ns/op",
            "extra": "320632473 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "320632473 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "320632473 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10",
            "value": 102855,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10 - ns/op",
            "value": 102855,
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
            "value": 102993,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - ns/op",
            "value": 102993,
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
            "value": 102988,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000 - ns/op",
            "value": 102988,
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
            "value": 445.7,
            "unit": "ns/op\t     229 B/op\t       3 allocs/op",
            "extra": "2690238 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - ns/op",
            "value": 445.7,
            "unit": "ns/op",
            "extra": "2690238 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - B/op",
            "value": 229,
            "unit": "B/op",
            "extra": "2690238 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2690238 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2",
            "value": 9196,
            "unit": "ns/op\t   17464 B/op\t      77 allocs/op",
            "extra": "123434 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - ns/op",
            "value": 9196,
            "unit": "ns/op",
            "extra": "123434 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - B/op",
            "value": 17464,
            "unit": "B/op",
            "extra": "123434 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - allocs/op",
            "value": 77,
            "unit": "allocs/op",
            "extra": "123434 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3",
            "value": 25238,
            "unit": "ns/op\t   47576 B/op\t     200 allocs/op",
            "extra": "47176 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - ns/op",
            "value": 25238,
            "unit": "ns/op",
            "extra": "47176 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - B/op",
            "value": 47576,
            "unit": "B/op",
            "extra": "47176 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - allocs/op",
            "value": 200,
            "unit": "allocs/op",
            "extra": "47176 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4",
            "value": 36514,
            "unit": "ns/op\t   69816 B/op\t     295 allocs/op",
            "extra": "32958 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - ns/op",
            "value": 36514,
            "unit": "ns/op",
            "extra": "32958 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - B/op",
            "value": 69816,
            "unit": "B/op",
            "extra": "32958 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - allocs/op",
            "value": 295,
            "unit": "allocs/op",
            "extra": "32958 times\n4 procs"
          }
        ]
      },
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
          "id": "cfa910b8f625ae17c9e0102fd65f1076e5c42f46",
          "message": "ci: update release workflows to Go 1.24 and replace deprecated macos-13 (#50)\n\nAll release workflows were using Go 1.21 (project requires 1.24).\nReplace deprecated macos-13 runner with macos-latest for Intel builds.",
          "timestamp": "2026-02-18T08:25:34-05:00",
          "tree_id": "4a4fea26f6f8249caddb80fb70c562fc1f38e12b",
          "url": "https://github.com/perplext/nsd/commit/cfa910b8f625ae17c9e0102fd65f1076e5c42f46"
        },
        "date": 1771421523868,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkProcessTLSPacket",
            "value": 594.8,
            "unit": "ns/op\t     208 B/op\t       8 allocs/op",
            "extra": "1992048 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - ns/op",
            "value": 594.8,
            "unit": "ns/op",
            "extra": "1992048 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - B/op",
            "value": 208,
            "unit": "B/op",
            "extra": "1992048 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessTLSPacket - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1992048 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes",
            "value": 6999,
            "unit": "ns/op\t    1588 B/op\t      93 allocs/op",
            "extra": "166760 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - ns/op",
            "value": 6999,
            "unit": "ns/op",
            "extra": "166760 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - B/op",
            "value": 1588,
            "unit": "B/op",
            "extra": "166760 times\n4 procs"
          },
          {
            "name": "BenchmarkHexToBytes - allocs/op",
            "value": 93,
            "unit": "allocs/op",
            "extra": "166760 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint",
            "value": 162.9,
            "unit": "ns/op\t      60 B/op\t       0 allocs/op",
            "extra": "7422050 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - ns/op",
            "value": 162.9,
            "unit": "ns/op",
            "extra": "7422050 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - B/op",
            "value": 60,
            "unit": "B/op",
            "extra": "7422050 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "7422050 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint",
            "value": 247.7,
            "unit": "ns/op\t     121 B/op\t       0 allocs/op",
            "extra": "4796438 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - ns/op",
            "value": 247.7,
            "unit": "ns/op",
            "extra": "4796438 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - B/op",
            "value": 121,
            "unit": "B/op",
            "extra": "4796438 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphAddDualPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4796438 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc",
            "value": 252.3,
            "unit": "ns/op\t      16 B/op\t       2 allocs/op",
            "extra": "4718808 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - ns/op",
            "value": 252.3,
            "unit": "ns/op",
            "extra": "4718808 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - B/op",
            "value": 16,
            "unit": "B/op",
            "extra": "4718808 times\n4 procs"
          },
          {
            "name": "BenchmarkFormatValueFunc - allocs/op",
            "value": 2,
            "unit": "allocs/op",
            "extra": "4718808 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint",
            "value": 1411,
            "unit": "ns/op\t      1000 datapoints\t     183 B/op\t       0 allocs/op",
            "extra": "881428 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - ns/op",
            "value": 1411,
            "unit": "ns/op",
            "extra": "881428 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - datapoints",
            "value": 1000,
            "unit": "datapoints",
            "extra": "881428 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - B/op",
            "value": 183,
            "unit": "B/op",
            "extra": "881428 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPoint - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "881428 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation",
            "value": 221.5,
            "unit": "ns/op\t     126 B/op\t       0 allocs/op",
            "extra": "5386734 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - ns/op",
            "value": 221.5,
            "unit": "ns/op",
            "extra": "5386734 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - B/op",
            "value": 126,
            "unit": "B/op",
            "extra": "5386734 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/AddDataPointWithRotation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "5386734 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData",
            "value": 242358,
            "unit": "ns/op\t  106800 B/op\t      13 allocs/op",
            "extra": "4652 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - ns/op",
            "value": 242358,
            "unit": "ns/op",
            "extra": "4652 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - B/op",
            "value": 106800,
            "unit": "B/op",
            "extra": "4652 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphDataOperations/ClearData - allocs/op",
            "value": 13,
            "unit": "allocs/op",
            "extra": "4652 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small",
            "value": 21828,
            "unit": "ns/op\t     724 B/op\t      59 allocs/op",
            "extra": "52309 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - ns/op",
            "value": 21828,
            "unit": "ns/op",
            "extra": "52309 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - B/op",
            "value": 724,
            "unit": "B/op",
            "extra": "52309 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "52309 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium",
            "value": 22076,
            "unit": "ns/op\t     726 B/op\t      59 allocs/op",
            "extra": "54692 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - ns/op",
            "value": 22076,
            "unit": "ns/op",
            "extra": "54692 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - B/op",
            "value": 726,
            "unit": "B/op",
            "extra": "54692 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "54692 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large",
            "value": 21877,
            "unit": "ns/op\t     733 B/op\t      59 allocs/op",
            "extra": "52867 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - ns/op",
            "value": 21877,
            "unit": "ns/op",
            "extra": "52867 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - B/op",
            "value": 733,
            "unit": "B/op",
            "extra": "52867 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-10pts-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "52867 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small",
            "value": 22087,
            "unit": "ns/op\t     704 B/op\t      60 allocs/op",
            "extra": "52563 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - ns/op",
            "value": 22087,
            "unit": "ns/op",
            "extra": "52563 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - B/op",
            "value": 704,
            "unit": "B/op",
            "extra": "52563 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52563 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium",
            "value": 22149,
            "unit": "ns/op\t     701 B/op\t      60 allocs/op",
            "extra": "52642 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - ns/op",
            "value": 22149,
            "unit": "ns/op",
            "extra": "52642 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - B/op",
            "value": 701,
            "unit": "B/op",
            "extra": "52642 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52642 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large",
            "value": 22168,
            "unit": "ns/op\t     710 B/op\t      60 allocs/op",
            "extra": "51850 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - ns/op",
            "value": 22168,
            "unit": "ns/op",
            "extra": "51850 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - B/op",
            "value": 710,
            "unit": "B/op",
            "extra": "51850 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-100pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "51850 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small",
            "value": 22239,
            "unit": "ns/op\t     703 B/op\t      60 allocs/op",
            "extra": "52567 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - ns/op",
            "value": 22239,
            "unit": "ns/op",
            "extra": "52567 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - B/op",
            "value": 703,
            "unit": "B/op",
            "extra": "52567 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Small - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52567 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium",
            "value": 22383,
            "unit": "ns/op\t     701 B/op\t      60 allocs/op",
            "extra": "52596 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - ns/op",
            "value": 22383,
            "unit": "ns/op",
            "extra": "52596 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - B/op",
            "value": 701,
            "unit": "B/op",
            "extra": "52596 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Medium - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "52596 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large",
            "value": 22705,
            "unit": "ns/op\t     707 B/op\t      60 allocs/op",
            "extra": "53863 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - ns/op",
            "value": 22705,
            "unit": "ns/op",
            "extra": "53863 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - B/op",
            "value": 707,
            "unit": "B/op",
            "extra": "53863 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/braille-1000pts-Large - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "53863 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small",
            "value": 20368,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "59974 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - ns/op",
            "value": 20368,
            "unit": "ns/op",
            "extra": "59974 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "59974 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59974 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium",
            "value": 20311,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "59625 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - ns/op",
            "value": 20311,
            "unit": "ns/op",
            "extra": "59625 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "59625 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59625 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large",
            "value": 20466,
            "unit": "ns/op\t     534 B/op\t      57 allocs/op",
            "extra": "57763 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - ns/op",
            "value": 20466,
            "unit": "ns/op",
            "extra": "57763 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - B/op",
            "value": 534,
            "unit": "B/op",
            "extra": "57763 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "57763 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small",
            "value": 20886,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "57978 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - ns/op",
            "value": 20886,
            "unit": "ns/op",
            "extra": "57978 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "57978 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57978 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium",
            "value": 20580,
            "unit": "ns/op\t     544 B/op\t      58 allocs/op",
            "extra": "56772 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - ns/op",
            "value": 20580,
            "unit": "ns/op",
            "extra": "56772 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - B/op",
            "value": 544,
            "unit": "B/op",
            "extra": "56772 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "56772 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large",
            "value": 20430,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "57037 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - ns/op",
            "value": 20430,
            "unit": "ns/op",
            "extra": "57037 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "57037 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57037 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small",
            "value": 20472,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "56682 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - ns/op",
            "value": 20472,
            "unit": "ns/op",
            "extra": "56682 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "56682 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "56682 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium",
            "value": 20299,
            "unit": "ns/op\t     544 B/op\t      58 allocs/op",
            "extra": "57124 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - ns/op",
            "value": 20299,
            "unit": "ns/op",
            "extra": "57124 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - B/op",
            "value": 544,
            "unit": "B/op",
            "extra": "57124 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57124 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large",
            "value": 20556,
            "unit": "ns/op\t     544 B/op\t      58 allocs/op",
            "extra": "56840 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - ns/op",
            "value": 20556,
            "unit": "ns/op",
            "extra": "56840 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - B/op",
            "value": 544,
            "unit": "B/op",
            "extra": "56840 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/block-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "56840 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small",
            "value": 20241,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "59698 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - ns/op",
            "value": 20241,
            "unit": "ns/op",
            "extra": "59698 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "59698 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "59698 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium",
            "value": 20439,
            "unit": "ns/op\t     533 B/op\t      57 allocs/op",
            "extra": "60984 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - ns/op",
            "value": 20439,
            "unit": "ns/op",
            "extra": "60984 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - B/op",
            "value": 533,
            "unit": "B/op",
            "extra": "60984 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60984 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large",
            "value": 20271,
            "unit": "ns/op\t     536 B/op\t      57 allocs/op",
            "extra": "60810 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - ns/op",
            "value": 20271,
            "unit": "ns/op",
            "extra": "60810 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - B/op",
            "value": 536,
            "unit": "B/op",
            "extra": "60810 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-10pts-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "60810 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small",
            "value": 20799,
            "unit": "ns/op\t     543 B/op\t      58 allocs/op",
            "extra": "58610 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - ns/op",
            "value": 20799,
            "unit": "ns/op",
            "extra": "58610 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - B/op",
            "value": 543,
            "unit": "B/op",
            "extra": "58610 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58610 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium",
            "value": 20811,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "58880 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - ns/op",
            "value": 20811,
            "unit": "ns/op",
            "extra": "58880 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "58880 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58880 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large",
            "value": 20827,
            "unit": "ns/op\t     544 B/op\t      58 allocs/op",
            "extra": "58947 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - ns/op",
            "value": 20827,
            "unit": "ns/op",
            "extra": "58947 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - B/op",
            "value": 544,
            "unit": "B/op",
            "extra": "58947 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-100pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "58947 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small",
            "value": 20358,
            "unit": "ns/op\t     541 B/op\t      58 allocs/op",
            "extra": "57014 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - ns/op",
            "value": 20358,
            "unit": "ns/op",
            "extra": "57014 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - B/op",
            "value": 541,
            "unit": "B/op",
            "extra": "57014 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Small - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57014 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium",
            "value": 20247,
            "unit": "ns/op\t     544 B/op\t      58 allocs/op",
            "extra": "57379 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - ns/op",
            "value": 20247,
            "unit": "ns/op",
            "extra": "57379 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - B/op",
            "value": 544,
            "unit": "B/op",
            "extra": "57379 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Medium - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "57379 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large",
            "value": 20367,
            "unit": "ns/op\t     542 B/op\t      58 allocs/op",
            "extra": "56784 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - ns/op",
            "value": 20367,
            "unit": "ns/op",
            "extra": "56784 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - B/op",
            "value": 542,
            "unit": "B/op",
            "extra": "56784 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/tty-1000pts-Large - allocs/op",
            "value": 58,
            "unit": "allocs/op",
            "extra": "56784 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration",
            "value": 5.631,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "212941341 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - ns/op",
            "value": 5.631,
            "unit": "ns/op",
            "extra": "212941341 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "212941341 times\n4 procs"
          },
          {
            "name": "BenchmarkBrailleGeneration - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "212941341 times\n4 procs"
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
            "value": 0.0000111,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkScaling - ns/op",
            "value": 0.0000111,
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
            "value": 40109,
            "unit": "ns/op\t    1362 B/op\t     114 allocs/op",
            "extra": "30043 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - ns/op",
            "value": 40109,
            "unit": "ns/op",
            "extra": "30043 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - B/op",
            "value": 1362,
            "unit": "B/op",
            "extra": "30043 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-2 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "30043 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4",
            "value": 40086,
            "unit": "ns/op\t    1364 B/op\t     114 allocs/op",
            "extra": "29902 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - ns/op",
            "value": 40086,
            "unit": "ns/op",
            "extra": "29902 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - B/op",
            "value": 1364,
            "unit": "B/op",
            "extra": "29902 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-4 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "29902 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8",
            "value": 40047,
            "unit": "ns/op\t    1369 B/op\t     114 allocs/op",
            "extra": "29985 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - ns/op",
            "value": 40047,
            "unit": "ns/op",
            "extra": "29985 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - B/op",
            "value": 1369,
            "unit": "B/op",
            "extra": "29985 times\n4 procs"
          },
          {
            "name": "BenchmarkMultiGraph/Graphs-8 - allocs/op",
            "value": 114,
            "unit": "allocs/op",
            "extra": "29985 times\n4 procs"
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
            "value": 6e-7,
            "unit": "ns/op\t      3610 datapoints\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkHistoricalData/24h0m0s - ns/op",
            "value": 6e-7,
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
            "value": 21863,
            "unit": "ns/op\t   53166 B/op\t      37 allocs/op",
            "extra": "58485 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - ns/op",
            "value": 21863,
            "unit": "ns/op",
            "extra": "58485 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - B/op",
            "value": 53166,
            "unit": "B/op",
            "extra": "58485 times\n4 procs"
          },
          {
            "name": "BenchmarkConcurrentDataAccess - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "58485 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation",
            "value": 55.47,
            "unit": "ns/op\t        32.00 bytes/point\t       0 B/op\t       0 allocs/op",
            "extra": "21493878 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - ns/op",
            "value": 55.47,
            "unit": "ns/op",
            "extra": "21493878 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - bytes/point",
            "value": 32,
            "unit": "bytes/point",
            "extra": "21493878 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21493878 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/DataPointAllocation - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21493878 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData",
            "value": 258791,
            "unit": "ns/op\t  123584 B/op\t      19 allocs/op",
            "extra": "4336 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - ns/op",
            "value": 258791,
            "unit": "ns/op",
            "extra": "4336 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - B/op",
            "value": 123584,
            "unit": "B/op",
            "extra": "4336 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/GraphWithData - allocs/op",
            "value": 19,
            "unit": "allocs/op",
            "extra": "4336 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing",
            "value": 5612,
            "unit": "ns/op\t 213493000 packets/op\t       0 B/op\t       0 allocs/op",
            "extra": "213493 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - ns/op",
            "value": 5612,
            "unit": "ns/op",
            "extra": "213493 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - packets/op",
            "value": 213493000,
            "unit": "packets/op",
            "extra": "213493 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "213493 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketProcessing - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "213493 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit",
            "value": 2.491,
            "unit": "ns/op\t       100.0 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "480966225 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - ns/op",
            "value": 2.491,
            "unit": "ns/op",
            "extra": "480966225 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allowed%",
            "value": 100,
            "unit": "allowed%",
            "extra": "480966225 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "480966225 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/NoLimit - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "480966225 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS",
            "value": 117.9,
            "unit": "ns/op\t         0.1277 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10172527 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - ns/op",
            "value": 117.9,
            "unit": "ns/op",
            "extra": "10172527 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allowed%",
            "value": 0.1277,
            "unit": "allowed%",
            "extra": "10172527 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10172527 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/10kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10172527 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS",
            "value": 117.9,
            "unit": "ns/op\t         1.277 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10193440 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - ns/op",
            "value": 117.9,
            "unit": "ns/op",
            "extra": "10193440 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allowed%",
            "value": 1.277,
            "unit": "allowed%",
            "extra": "10193440 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10193440 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/100kPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10193440 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS",
            "value": 118.6,
            "unit": "ns/op\t        12.84 allowed%\t       0 B/op\t       0 allocs/op",
            "extra": "10205403 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - ns/op",
            "value": 118.6,
            "unit": "ns/op",
            "extra": "10205403 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allowed%",
            "value": 12.84,
            "unit": "allowed%",
            "extra": "10205403 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "10205403 times\n4 procs"
          },
          {
            "name": "BenchmarkRateLimiting/1MPPS - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "10205403 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool",
            "value": 325.7,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "3681996 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - ns/op",
            "value": 325.7,
            "unit": "ns/op",
            "extra": "3681996 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "3681996 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "3681996 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool",
            "value": 2673,
            "unit": "ns/op\t   14560 B/op\t       1 allocs/op",
            "extra": "391861 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - ns/op",
            "value": 2673,
            "unit": "ns/op",
            "extra": "391861 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - B/op",
            "value": 14560,
            "unit": "B/op",
            "extra": "391861 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryPool/WithoutPool - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "391861 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController",
            "value": 336.7,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3560936 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - ns/op",
            "value": 336.7,
            "unit": "ns/op",
            "extra": "3560936 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3560936 times\n4 procs"
          },
          {
            "name": "BenchmarkResourceController - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3560936 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64",
            "value": 5.298,
            "unit": "ns/op\t12080.22 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226475686 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - ns/op",
            "value": 5.298,
            "unit": "ns/op",
            "extra": "226475686 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - MB/s",
            "value": 12080.22,
            "unit": "MB/s",
            "extra": "226475686 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226475686 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-64 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226475686 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256",
            "value": 5.296,
            "unit": "ns/op\t48335.26 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226507170 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - ns/op",
            "value": 5.296,
            "unit": "ns/op",
            "extra": "226507170 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - MB/s",
            "value": 48335.26,
            "unit": "MB/s",
            "extra": "226507170 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226507170 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-256 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226507170 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512",
            "value": 5.313,
            "unit": "ns/op\t96364.16 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226540419 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - ns/op",
            "value": 5.313,
            "unit": "ns/op",
            "extra": "226540419 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - MB/s",
            "value": 96364.16,
            "unit": "MB/s",
            "extra": "226540419 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226540419 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-512 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226540419 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024",
            "value": 5.295,
            "unit": "ns/op\t193385.90 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226627222 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - ns/op",
            "value": 5.295,
            "unit": "ns/op",
            "extra": "226627222 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - MB/s",
            "value": 193385.9,
            "unit": "MB/s",
            "extra": "226627222 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226627222 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1024 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226627222 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500",
            "value": 5.346,
            "unit": "ns/op\t280602.32 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "225856112 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - ns/op",
            "value": 5.346,
            "unit": "ns/op",
            "extra": "225856112 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - MB/s",
            "value": 280602.32,
            "unit": "MB/s",
            "extra": "225856112 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "225856112 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-1500 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "225856112 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000",
            "value": 5.298,
            "unit": "ns/op\t1698911.38 MB/s\t       0 B/op\t       0 allocs/op",
            "extra": "226436804 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - ns/op",
            "value": 5.298,
            "unit": "ns/op",
            "extra": "226436804 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - MB/s",
            "value": 1698911.38,
            "unit": "MB/s",
            "extra": "226436804 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "226436804 times\n4 procs"
          },
          {
            "name": "BenchmarkPacketSizes/Size-9000 - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "226436804 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline",
            "value": 54654,
            "unit": "ns/op\t         0 MB/op\t       0 B/op\t       0 allocs/op",
            "extra": "21806 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - ns/op",
            "value": 54654,
            "unit": "ns/op",
            "extra": "21806 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - MB/op",
            "value": 0,
            "unit": "MB/op",
            "extra": "21806 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "21806 times\n4 procs"
          },
          {
            "name": "BenchmarkMemoryUsage/Baseline - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "21806 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple",
            "value": 92.6,
            "unit": "ns/op\t      24 B/op\t       1 allocs/op",
            "extra": "13233520 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - ns/op",
            "value": 92.6,
            "unit": "ns/op",
            "extra": "13233520 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - B/op",
            "value": 24,
            "unit": "B/op",
            "extra": "13233520 times\n4 procs"
          },
          {
            "name": "BenchmarkIsProtocolTrafficSimple - allocs/op",
            "value": 1,
            "unit": "allocs/op",
            "extra": "13233520 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID",
            "value": 274.9,
            "unit": "ns/op\t      61 B/op\t       3 allocs/op",
            "extra": "4322203 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - ns/op",
            "value": 274.9,
            "unit": "ns/op",
            "extra": "4322203 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - B/op",
            "value": 61,
            "unit": "B/op",
            "extra": "4322203 times\n4 procs"
          },
          {
            "name": "BenchmarkGenerateEventID - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "4322203 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket",
            "value": 262.1,
            "unit": "ns/op\t    3411 B/op\t       0 allocs/op",
            "extra": "4967360 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - ns/op",
            "value": 262.1,
            "unit": "ns/op",
            "extra": "4967360 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - B/op",
            "value": 3411,
            "unit": "B/op",
            "extra": "4967360 times\n4 procs"
          },
          {
            "name": "BenchmarkProcessPacket - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4967360 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small",
            "value": 22329,
            "unit": "ns/op\t     724 B/op\t      59 allocs/op",
            "extra": "53768 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - ns/op",
            "value": 22329,
            "unit": "ns/op",
            "extra": "53768 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - B/op",
            "value": 724,
            "unit": "B/op",
            "extra": "53768 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Small - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53768 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium",
            "value": 22190,
            "unit": "ns/op\t     725 B/op\t      59 allocs/op",
            "extra": "53233 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - ns/op",
            "value": 22190,
            "unit": "ns/op",
            "extra": "53233 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - B/op",
            "value": 725,
            "unit": "B/op",
            "extra": "53233 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Medium - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53233 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large",
            "value": 22245,
            "unit": "ns/op\t     723 B/op\t      59 allocs/op",
            "extra": "53294 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - ns/op",
            "value": 22245,
            "unit": "ns/op",
            "extra": "53294 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - B/op",
            "value": 723,
            "unit": "B/op",
            "extra": "53294 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Braille-Large - allocs/op",
            "value": 59,
            "unit": "allocs/op",
            "extra": "53294 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small",
            "value": 20195,
            "unit": "ns/op\t     532 B/op\t      57 allocs/op",
            "extra": "57387 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - ns/op",
            "value": 20195,
            "unit": "ns/op",
            "extra": "57387 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - B/op",
            "value": 532,
            "unit": "B/op",
            "extra": "57387 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "57387 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium",
            "value": 20277,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58635 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - ns/op",
            "value": 20277,
            "unit": "ns/op",
            "extra": "58635 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58635 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58635 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large",
            "value": 20309,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58377 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - ns/op",
            "value": 20309,
            "unit": "ns/op",
            "extra": "58377 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58377 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/Block-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58377 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small",
            "value": 20063,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58885 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - ns/op",
            "value": 20063,
            "unit": "ns/op",
            "extra": "58885 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58885 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Small - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58885 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium",
            "value": 20075,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58586 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - ns/op",
            "value": 20075,
            "unit": "ns/op",
            "extra": "58586 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58586 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Medium - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58586 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large",
            "value": 20490,
            "unit": "ns/op\t     530 B/op\t      57 allocs/op",
            "extra": "58563 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - ns/op",
            "value": 20490,
            "unit": "ns/op",
            "extra": "58563 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - B/op",
            "value": 530,
            "unit": "B/op",
            "extra": "58563 times\n4 procs"
          },
          {
            "name": "BenchmarkGraphRendering/TTY-Large - allocs/op",
            "value": 57,
            "unit": "allocs/op",
            "extra": "58563 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix",
            "value": 45011,
            "unit": "ns/op\t   28843 B/op\t     355 allocs/op",
            "extra": "27574 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - ns/op",
            "value": 45011,
            "unit": "ns/op",
            "extra": "27574 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - B/op",
            "value": 28843,
            "unit": "B/op",
            "extra": "27574 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Matrix - allocs/op",
            "value": 355,
            "unit": "allocs/op",
            "extra": "27574 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap",
            "value": 6449,
            "unit": "ns/op\t    3696 B/op\t      52 allocs/op",
            "extra": "179209 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - ns/op",
            "value": 6449,
            "unit": "ns/op",
            "extra": "179209 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - B/op",
            "value": 3696,
            "unit": "B/op",
            "extra": "179209 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Heatmap - allocs/op",
            "value": 52,
            "unit": "allocs/op",
            "extra": "179209 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer",
            "value": 9891,
            "unit": "ns/op\t    7257 B/op\t      34 allocs/op",
            "extra": "120344 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - ns/op",
            "value": 9891,
            "unit": "ns/op",
            "extra": "120344 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - B/op",
            "value": 7257,
            "unit": "B/op",
            "extra": "120344 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Speedometer - allocs/op",
            "value": 34,
            "unit": "allocs/op",
            "extra": "120344 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey",
            "value": 2395,
            "unit": "ns/op\t    1400 B/op\t      27 allocs/op",
            "extra": "451770 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - ns/op",
            "value": 2395,
            "unit": "ns/op",
            "extra": "451770 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - B/op",
            "value": 1400,
            "unit": "B/op",
            "extra": "451770 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Sankey - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "451770 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial",
            "value": 16721,
            "unit": "ns/op\t   16466 B/op\t      98 allocs/op",
            "extra": "71337 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - ns/op",
            "value": 16721,
            "unit": "ns/op",
            "extra": "71337 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - B/op",
            "value": 16466,
            "unit": "B/op",
            "extra": "71337 times\n4 procs"
          },
          {
            "name": "BenchmarkVisualizationUpdate/Radial - allocs/op",
            "value": 98,
            "unit": "allocs/op",
            "extra": "71337 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor",
            "value": 8.813,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "137343976 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - ns/op",
            "value": 8.813,
            "unit": "ns/op",
            "extra": "137343976 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "137343976 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/GetUsageColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "137343976 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor",
            "value": 24.15,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "49741806 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - ns/op",
            "value": 24.15,
            "unit": "ns/op",
            "extra": "49741806 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "49741806 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/InterpolateColor - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "49741806 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex",
            "value": 36.2,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "32611856 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - ns/op",
            "value": 36.2,
            "unit": "ns/op",
            "extra": "32611856 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "32611856 times\n4 procs"
          },
          {
            "name": "BenchmarkThemeOperations/ParseHex - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "32611856 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow",
            "value": 6.539,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "183381784 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - ns/op",
            "value": 6.539,
            "unit": "ns/op",
            "extra": "183381784 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "183381784 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Rainbow - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "183381784 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse",
            "value": 18.49,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "64650117 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - ns/op",
            "value": 18.49,
            "unit": "ns/op",
            "extra": "64650117 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "64650117 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Pulse - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "64650117 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire",
            "value": 5.918,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "202824528 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - ns/op",
            "value": 5.918,
            "unit": "ns/op",
            "extra": "202824528 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "202824528 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Fire - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "202824528 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix",
            "value": 3.746,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "319634352 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - ns/op",
            "value": 3.746,
            "unit": "ns/op",
            "extra": "319634352 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "319634352 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Matrix - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "319634352 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave",
            "value": 32.24,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "36999574 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - ns/op",
            "value": 32.24,
            "unit": "ns/op",
            "extra": "36999574 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "36999574 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Wave - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "36999574 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle",
            "value": 3.739,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "320853758 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - ns/op",
            "value": 3.739,
            "unit": "ns/op",
            "extra": "320853758 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "320853758 times\n4 procs"
          },
          {
            "name": "BenchmarkAnimations/Sparkle - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "320853758 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10",
            "value": 103026,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-10 - ns/op",
            "value": 103026,
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
            "value": 103489,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-100 - ns/op",
            "value": 103489,
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
            "value": 103426,
            "unit": "ns/op\t    5176 B/op\t     196 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkConnectionTable/Connections-1000 - ns/op",
            "value": 103426,
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
            "value": 449.3,
            "unit": "ns/op\t     229 B/op\t       3 allocs/op",
            "extra": "2658537 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - ns/op",
            "value": 449.3,
            "unit": "ns/op",
            "extra": "2658537 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - B/op",
            "value": 229,
            "unit": "B/op",
            "extra": "2658537 times\n4 procs"
          },
          {
            "name": "BenchmarkStatusBarUpdate - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2658537 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2",
            "value": 9421,
            "unit": "ns/op\t   17464 B/op\t      77 allocs/op",
            "extra": "121886 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - ns/op",
            "value": 9421,
            "unit": "ns/op",
            "extra": "121886 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - B/op",
            "value": 17464,
            "unit": "B/op",
            "extra": "121886 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/2x2 - allocs/op",
            "value": 77,
            "unit": "allocs/op",
            "extra": "121886 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3",
            "value": 26615,
            "unit": "ns/op\t   47576 B/op\t     200 allocs/op",
            "extra": "45344 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - ns/op",
            "value": 26615,
            "unit": "ns/op",
            "extra": "45344 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - B/op",
            "value": 47576,
            "unit": "B/op",
            "extra": "45344 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/3x3 - allocs/op",
            "value": 200,
            "unit": "allocs/op",
            "extra": "45344 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4",
            "value": 38109,
            "unit": "ns/op\t   69816 B/op\t     295 allocs/op",
            "extra": "31027 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - ns/op",
            "value": 38109,
            "unit": "ns/op",
            "extra": "31027 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - B/op",
            "value": 69816,
            "unit": "B/op",
            "extra": "31027 times\n4 procs"
          },
          {
            "name": "BenchmarkDashboardLayout/4x4 - allocs/op",
            "value": 295,
            "unit": "allocs/op",
            "extra": "31027 times\n4 procs"
          }
        ]
      }
    ]
  }
}