All times are milliseconds per API call; Go values are medians of repeated runs.

| Group | Set | C keygen | Go keygen | Go DIT keygen | C exchange | Go exchange | Go DIT exchange |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fast I | p308_633 | 0.651 | 5.490 | 5.891 | 4.86 | 46.319 | 50.293 |
| Fast III | p474_593 | 2.11 | 12.512 | 15.631 | 15 | 103.672 | 118.577 |
| Fast V | p628_317 | 4.16 | 21.871 | 23.254 | 28.6 | 176.949 | 188.160 |
| Rigorous I | p374_117 | 1.49 | 10.647 | 11.702 | 10.5 | 88.441 | 97.217 |
| Rigorous III | p566_77 | 4.55 | 25.235 | 27.741 | 31.3 | 205.036 | 219.799 |
| Rigorous V | p758_41 | 11.2 | 48.197 | 50.488 | 69.9 | 378.831 | 399.009 |

Allocations below are for the default API; MiB/op counts total bytes allocated, not peak memory.

| Set | Keygen MiB/op | Keygen allocs/op | Exchange MiB/op | Exchange allocs/op |
| --- | ---: | ---: | ---: | ---: |
| p308_633 | 6.58 | 191,552 | 56.31 | 1,619,587 |
| p474_593 | 12.66 | 301,604 | 108.17 | 2,553,470 |
| p628_317 | 20.62 | 415,876 | 176.04 | 3,524,197 |
| p374_117 | 11.48 | 334,296 | 97.23 | 2,795,229 |
| p566_77 | 26.46 | 533,448 | 223.82 | 4,480,157 |
| p758_41 | 42.53 | 743,280 | 358.19 | 6,223,993 |
