# Seedlab Week #9 (Secret Key Encryption)

# Task 1: Frequency Analysis

For this first task, the objective is to decypher the contents of the `ciphertext.txt` file. This file contains an English message that was encrypted using a monoalphabetic substitution cipher, where each letter of the original text is mapped to a different letter in the encrypted text (for example, every `a` is replaced with `j`, every `b` is replaced with `f`, and so on). In order for it to decrypted, it is also implicit that each letter can only correspond to a single letter (otherwise, if for example `a` and `b` were both replaced by `m` we wouldn't be able to revert the substitution).

In order to decypher the text, the recommended approach is to analyze the frequencies of single letters, bigrams (two consecutive letters) and trigrams (three consecutive letters). Since we know the original text is English, we can analyze the common frequencies of each of those and try letter by letter to convert the text. To help with this, we use the `tr` command in the following manner: `tr <encrypted-characters> <original-characters> < ciphertext.txt > message.txt`.

By running the `freq.py` script, we will get output of the absolute frequencies of letters, bigrams and trigrams. We can see the typical cryptanalytic frequency of each of those in the wikipedia links of the task description:
- [Single Characters](https://en.wikipedia.org/wiki/Frequency_analysis)
- [Bigrams](https://en.wikipedia.org/wiki/Bigram)
- [Trigrams](https://en.wikipedia.org/wiki/Trigram)

A good start is the most common trigram `ytn` whose frequency is far higher than all the other trigrams and contains two of the most frequent characters `y` and `n` with a mildly common letter in between `t`. This trigram should correspond to `the`, so the first attempt was `tr "ytn" "THE" < ciphertext.txt > message.txt`.

From now on, we just kept using frequency analysis and reading the output of the `message.txt` to see if we could decrypt any words contextually, until we got the full 26-character mapping. Below are the sequence of steps we followed:

| Cipher | Original | Justification                              |
| :----: | :------: | ------------------------------------------ |
|  `v`   |   `A`    | Frequency analysis and the `vT` and `THvT` |
|  `x`   |   `O`    | Frequency analysis and the `Tx`            |
|  `i`   |   `L`    | Frequency analysis and the `Aii`           |
|  `h`   |   `R`    | Frequency analysis and the `Oh` `AhE`      |
|  `q`   |   `S`    | Frequency analysis and the `THOqE`         |
|  `b`   |   `F`    | Frequency analysis and the `ALL Ob THOSE`  |
|  `m`   |   `I`    | Frequency analysis and the `HmSTORmaAL`    |
|  `a`   |   `C`    | Frequency analysis and the `HISTORIaAL`    |
|  `g`   |   `B`    | Frequency analysis and the `gEST`          |
|  `p`   |   `D`    | Frequency analysis and the `pIRECTOR`      |
|  `l`   |   `W`    | Frequency analysis and the `AlARDS`        |
|  `u`   |   `N`    | Frequency analysis and the `AnD`           |
|  `r`   |   `G`    | Frequency analysis and the `EARNINr`       |
|  `c`   |   `M`    | Frequency analysis and the `NOcINATIONS`   |
|  `z`   |   `U`    | Frequency analysis and the `WITHOzT`       |
|  `e`   |   `P`    | Frequency analysis and the `eICTURE`       |
|  `d`   |   `Y`    | Frequency analysis and the `TERRIBLd`      |
|  `f`   |   `V`    | Frequency analysis and the `ACTIfISM`      |
|  `s`   |   `K`    | Frequency analysis and the `LIsE`          |
|  `o`   |   `J`    | Frequency analysis and the `oUST`          |
|  `j`   |   `Q`    | Frequency analysis and the `jUESTION`      |
|  `k`   |   `X`    | Frequency analysis and the `EkTRA`         |
|  `w`   |   `Z`    | Frequency analysis and the `PRIwE`         |

By adding on to the `tr` command we should end up with something similar to this:

```sh
tr "ytnvxihqbmagplurczedfsojkw" "THEAOLRSFICBDWNGMUPYVKJQXZ" < ciphertext.txt > message.txt
```

The final mapping of characters between the original and encrypted message is shown below:

|          Original          |         Encrypted          |
| :------------------------: | :------------------------: |
| ABCDEFGHIJKLMNOPQRSTUVWXYZ | VGAPNBRTMOSICUXEJHQYZFLKDW |
| CFMYPVBRLQXWIEJDSGKHNAZOTU | ABCDEFGHIJKLMNOPQRSTUVWXYZ |

The final message after decrypting the monoalphabetic substitution cypher is:

```
THE OSCARS TURN  ON SUNDAY WHICH SEEMS ABOUT RIGHT AFTER THIS LONG STRANGE
AWARDS TRIP THE BAGGER FEELS LIKE A NONAGENARIAN TOO

THE AWARDS RACE WAS BOOKENDED BY THE DEMISE OF HARVEY WEINSTEIN AT ITS OUTSET
AND THE APPARENT IMPLOSION OF HIS FILM COMPANY AT THE END AND IT WAS SHAPED BY
THE EMERGENCE OF METOO TIMES UP BLACKGOWN POLITICS ARMCANDY ACTIVISM AND
A NATIONAL CONVERSATION AS BRIEF AND MAD AS A FEVER DREAM ABOUT WHETHER THERE
OUGHT TO BE A PRESIDENT WINFREY THE SEASON DIDNT JUST SEEM EXTRA LONG IT WAS
EXTRA LONG BECAUSE THE OSCARS WERE MOVED TO THE FIRST WEEKEND IN MARCH TO
AVOID CONFLICTING WITH THE CLOSING CEREMONY OF THE WINTER OLYMPICS THANKS
PYEONGCHANG

ONE BIG QUESTION SURROUNDING THIS YEARS ACADEMY AWARDS IS HOW OR IF THE
CEREMONY WILL ADDRESS METOO ESPECIALLY AFTER THE GOLDEN GLOBES WHICH BECAME
A JUBILANT COMINGOUT PARTY FOR TIMES UP THE MOVEMENT SPEARHEADED BY 
POWERFUL HOLLYWOOD WOMEN WHO HELPED RAISE MILLIONS OF DOLLARS TO FIGHT SEXUAL
HARASSMENT AROUND THE COUNTRY

SIGNALING THEIR SUPPORT GOLDEN GLOBES ATTENDEES SWATHED THEMSELVES IN BLACK
SPORTED LAPEL PINS AND SOUNDED OFF ABOUT SEXIST POWER IMBALANCES FROM THE RED
CARPET AND THE STAGE ON THE AIR E WAS CALLED OUT ABOUT PAY INEQUITY AFTER
ITS FORMER ANCHOR CATT SADLER QUIT ONCE SHE LEARNED THAT SHE WAS MAKING FAR
LESS THAN A MALE COHOST AND DURING THE CEREMONY NATALIE PORTMAN TOOK A BLUNT
AND SATISFYING DIG AT THE ALLMALE ROSTER OF NOMINATED DIRECTORS HOW COULD
THAT BE TOPPED

AS IT TURNS OUT AT LEAST IN TERMS OF THE OSCARS IT PROBABLY WONT BE

WOMEN INVOLVED IN TIMES UP SAID THAT ALTHOUGH THE GLOBES SIGNIFIED THE
INITIATIVES LAUNCH THEY NEVER INTENDED IT TO BE JUST AN AWARDS SEASON
CAMPAIGN OR ONE THAT BECAME ASSOCIATED ONLY WITH REDCARPET ACTIONS INSTEAD
A SPOKESWOMAN SAID THE GROUP IS WORKING BEHIND CLOSED DOORS AND HAS SINCE
AMASSED  MILLION FOR ITS LEGAL DEFENSE FUND WHICH AFTER THE GLOBES WAS
FLOODED WITH THOUSANDS OF DONATIONS OF  OR LESS FROM PEOPLE IN SOME 
COUNTRIES


NO CALL TO WEAR BLACK GOWNS WENT OUT IN ADVANCE OF THE OSCARS THOUGH THE
MOVEMENT WILL ALMOST CERTAINLY BE REFERENCED BEFORE AND DURING THE CEREMONY 
ESPECIALLY SINCE VOCAL METOO SUPPORTERS LIKE ASHLEY JUDD LAURA DERN AND
NICOLE KIDMAN ARE SCHEDULED PRESENTERS

ANOTHER FEATURE OF THIS SEASON NO ONE REALLY KNOWS WHO IS GOING TO WIN BEST
PICTURE ARGUABLY THIS HAPPENS A LOT OF THE TIME INARGUABLY THE NAILBITER
NARRATIVE ONLY SERVES THE AWARDS HYPE MACHINE BUT OFTEN THE PEOPLE FORECASTING
THE RACE SOCALLED OSCAROLOGISTS CAN MAKE ONLY EDUCATED GUESSES

THE WAY THE ACADEMY TABULATES THE BIG WINNER DOESNT HELP IN EVERY OTHER
CATEGORY THE NOMINEE WITH THE MOST VOTES WINS BUT IN THE BEST PICTURE
CATEGORY VOTERS ARE ASKED TO LIST THEIR TOP MOVIES IN PREFERENTIAL ORDER IF A
MOVIE GETS MORE THAN  PERCENT OF THE FIRSTPLACE VOTES IT WINS WHEN NO
MOVIE MANAGES THAT THE ONE WITH THE FEWEST FIRSTPLACE VOTES IS ELIMINATED AND
ITS VOTES ARE REDISTRIBUTED TO THE MOVIES THAT GARNERED THE ELIMINATED BALLOTS
SECONDPLACE VOTES AND THIS CONTINUES UNTIL A WINNER EMERGES

IT IS ALL TERRIBLY CONFUSING BUT APPARENTLY THE CONSENSUS FAVORITE COMES OUT
AHEAD IN THE END THIS MEANS THAT ENDOFSEASON AWARDS CHATTER INVARIABLY
INVOLVES TORTURED SPECULATION ABOUT WHICH FILM WOULD MOST LIKELY BE VOTERS
SECOND OR THIRD FAVORITE AND THEN EQUALLY TORTURED CONCLUSIONS ABOUT WHICH
FILM MIGHT PREVAIL

IN  IT WAS A TOSSUP BETWEEN BOYHOOD AND THE EVENTUAL WINNER BIRDMAN
IN  WITH LOTS OF EXPERTS BETTING ON THE REVENANT OR THE BIG SHORT THE
PRIZE WENT TO SPOTLIGHT LAST YEAR NEARLY ALL THE FORECASTERS DECLARED LA
LA LAND THE PRESUMPTIVE WINNER AND FOR TWO AND A HALF MINUTES THEY WERE
CORRECT BEFORE AN ENVELOPE SNAFU WAS REVEALED AND THE RIGHTFUL WINNER
MOONLIGHT WAS CROWNED

THIS YEAR AWARDS WATCHERS ARE UNEQUALLY DIVIDED BETWEEN THREE BILLBOARDS
OUTSIDE EBBING MISSOURI THE FAVORITE AND THE SHAPE OF WATER WHICH IS
THE BAGGERS PREDICTION WITH A FEW FORECASTING A HAIL MARY WIN FOR GET OUT

BUT ALL OF THOSE FILMS HAVE HISTORICAL OSCARVOTING PATTERNS AGAINST THEM THE
SHAPE OF WATER HAS  NOMINATIONS MORE THAN ANY OTHER FILM AND WAS ALSO
NAMED THE YEARS BEST BY THE PRODUCERS AND DIRECTORS GUILDS YET IT WAS NOT
NOMINATED FOR A SCREEN ACTORS GUILD AWARD FOR BEST ENSEMBLE AND NO FILM HAS
WON BEST PICTURE WITHOUT PREVIOUSLY LANDING AT LEAST THE ACTORS NOMINATION
SINCE BRAVEHEART IN  THIS YEAR THE BEST ENSEMBLE SAG ENDED UP GOING TO
THREE BILLBOARDS WHICH IS SIGNIFICANT BECAUSE ACTORS MAKE UP THE ACADEMYS
LARGEST BRANCH THAT FILM WHILE DIVISIVE ALSO WON THE BEST DRAMA GOLDEN GLOBE
AND THE BAFTA BUT ITS FILMMAKER MARTIN MCDONAGH WAS NOT NOMINATED FOR BEST
DIRECTOR AND APART FROM ARGO MOVIES THAT LAND BEST PICTURE WITHOUT ALSO
EARNING BEST DIRECTOR NOMINATIONS ARE FEW AND FAR BETWEEN
```

> Note: After completing this task, we used the website [dcode.fr](https://www.dcode.fr/en) to validate the substitution  
> This website contains a lot of useful tools (many of them related to ciphers) including [this one](https://www.dcode.fr/monoalphabetic-substitution) to solve monoalphabetic substitution in different languages (including English) and with different variations and parameters

# Task 2



# Task 5


