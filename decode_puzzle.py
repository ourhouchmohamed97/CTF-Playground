text = """
Dragons slept across the evergreen. eagles soared silently over the peaks. Shadows moved slowly among the echoes. campfires glimmered near the 123ruins. lanterns shone faintly across the 0valley. 0ld maps revealed hidden knolls. _caves echoed softly with crystals. 1mages glowed brightly along the 0ridge. serpents slithered quietly under the 3stones. rivers shimmered gently beside the _marsh. yawning cliffs sheltered small 0nests. under canopies, creatures _waited. winds whispered over tall 1solated. light shimmered across looming looms. _hidden pathways led to fractured falls. 1llusions glimmered in narrow nooks. deep within the cave, echoes _rolled. mountains rose above the 3peaks. _stones scattered across the 1plain. night fell silently over _woods. 7hick fog covered the hills. 3rd river ran beneath the _bridge. whispering leaves danced along hollow. 1lluminated lanterns guided the 7h. 3mall streams glistened beneath _arces. shrubs swayed near the pebbles. 4ootprints led across cliff. 3ld oak trees marked secret spaces. _moss covered the hidden boulder. 3ddies of water spun past twisting . whisps of fog lingered near 3rocks. 3arth trembled slightly beneath northern. 125 nsects hummed softly through 2imeless nights.
"""

import re
from collections import defaultdict

# Extract tokens that start with digits or underscore
tokens = re.findall(r"(?:(?:\d+)|_)[A-Za-z]*|\d+\b", text)
# The above also catches standalone numbers like '125'
# Build a more careful scan maintaining original order
parts = []
for m in re.finditer(r"(\d+[A-Za-z]*|_[A-Za-z]+)", text):
    parts.append(m.group(0))

print('Extracted parts:', parts)

# Helper functions
leet = {'0':'O','1':'I','2':'Z','3':'E','4':'A','5':'S','6':'G','7':'T','8':'B','9':'g'}

# Strategy 1: for each numeric prefix, take letters at positions equal to each digit (0-based and 1-based)
def strategy_index(parts, one_based=False):
    out = []
    for p in parts:
        if p.startswith('_'):
            out.append(' ')
        else:
            m = re.match(r"(\d+)([A-Za-z]*)", p)
            if not m:
                continue
            nums, w = m.group(1), m.group(2)
            letters = []
            for ch in nums:
                idx = int(ch) - (1 if one_based else 0)
                if 0 <= idx < len(w):
                    letters.append(w[idx])
                else:
                    letters.append('?')
            out.append(''.join(letters))
    return ''.join(out)

# Strategy 2: take first letter after numeric prefix (or after underscore), optionally shift by sum of digits
import string

def caesar(ch, shift):
    if not ch.isalpha():
        return ch
    base = 'A' if ch.isupper() else 'a'
    return chr((ord(ch) - ord(base) + shift) % 26 + ord(base))

def strategy_first_shift(parts, shift_by_sum=True, leet_replace=False):
    out = []
    for p in parts:
        if p.startswith('_'):
            out.append(' ')
        else:
            m = re.match(r"(\d+)([A-Za-z]*)", p)
            if not m:
                continue
            nums, w = m.group(1), m.group(2)
            if leet_replace:
                # replace numeric prefix by leet mapping and use the entire word with that letter as first
                first = ''.join(leet.get(d,'?') for d in nums)
                # take first char of resulting string
                ch = first[0] if first else (w[0] if w else '?')
                out.append(ch)
            else:
                ch = w[0] if w else '?'
                if shift_by_sum:
                    s = sum(int(d) for d in nums)
                    out.append(caesar(ch, s))
                else:
                    out.append(ch)
    return ''.join(out)

# Strategy 3: leet-substitute digits in-place and then take first letters of each such word
def strategy_leet_first(parts):
    out = []
    for p in parts:
        if p.startswith('_'):
            out.append(' ')
        else:
            m = re.match(r"(\d+)([A-Za-z]*)", p)
            if not m:
                continue
            nums, w = m.group(1), m.group(2)
            # map each digit to leet letter and prepend to word
            mapped = ''.join(leet.get(d,'?') for d in nums) + w
            out.append(mapped[0])
    return ''.join(out)

# Try all strategies
candidates = {}
candidates['index_0_based'] = strategy_index(parts, one_based=False)
candidates['index_1_based'] = strategy_index(parts, one_based=True)
candidates['first_no_shift'] = strategy_first_shift(parts, shift_by_sum=False)
candidates['first_shift_sum'] = strategy_first_shift(parts, shift_by_sum=True)
candidates['first_leet'] = strategy_leet_first(parts)

for k,v in candidates.items():
    print(f"\n{ k }:\n{ v }")

# Also try extracting just the letters immediately after digits/underscores (no shift)
def immediate_letters(parts):
    out = []
    for p in parts:
        if p.startswith('_'):
            out.append(' ')
        else:
            m = re.match(r"(\d+)([A-Za-z]*)", p)
            if m:
                w = m.group(2)
                out.append(w[0] if w else '?')
    return ''.join(out)

print('\nimmediate_letters:\n', immediate_letters(parts))

# Print more info: the parts list with indices and splits
print('\nDetailed parts with numeric prefixes:')
for p in parts:
    if p.startswith('_'):
        print(p)
    else:
        m = re.match(r"(\d+)([A-Za-z]*)", p)
        if m:
            print(p, 'nums=', m.group(1), 'word=', m.group(2))

# Heuristic: try reading immediate letters and attempt simple Caesar shifts (0-25) to find English words
imm = immediate_letters(parts).replace(' ', '_')
print('\nTrying Caesar shifts on immediate letters (underscores kept as spaces):')
for s in range(26):
    transformed = ''.join(caesar(ch, s) if ch.isalpha() else ch for ch in imm)
    print('shift', s, transformed)

print('\nDone')

# Strategy 4: interpret numeric prefixes as ASCII codes when printable, underscores as spaces
def strategy_ascii(parts):
    out = []
    for p in parts:
        if p.startswith('_'):
            out.append(' ')
        else:
            m = re.match(r"(\d+)([A-Za-z]*)", p)
            if not m:
                continue
            nums = int(m.group(1))
            if 32 <= nums <= 126:
                out.append(chr(nums))
            else:
                # fall back: for single digit try leet map, else put '?'
                s = str(nums)
                if len(s) == 1 and s in leet:
                    out.append(leet[s])
                else:
                    out.append('?')
    return ''.join(out)

print('\nASCII-mapped prefixes:\n', strategy_ascii(parts))
