import base64
import re
import sys
from typing import ClassVar, Final, Iterator, TypeVar, overload
import urllib.parse

# Regarding the IDNA valid unicode codepoints:
#     c.f. https://www.rfc-editor.org/rfc/rfc5892
# Regarding the registered URI schemes:
#     c.f. https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml
# Regarding the IPv4/IPv6 address regexes:
#     c.f. https://stackoverflow.com/questions/53497

########################################################################################


# this is likely not 100% complete, but it's a reasonably decent subset of the unicode
# codepoints allowed in IDNA domain names, as per RFC5892, appendix B
STR_CHAR: Final = (
    r"""
        \u002D \u0030-\u0039 \u0061-\u007A \u00B7 \u00DF-\u00F6 \u00F8-\u00FF \u0101
        \u0103 \u0105 \u0107 \u0109 \u010B \u010D \u010F \u0111 \u0113 \u0115 \u0117
        \u0119 \u011B \u011D \u011F \u0121 \u0123 \u0125 \u0127 \u0129 \u012B \u012D
        \u012F \u0131 \u0135 \u0137-\u0138 \u013A \u013C \u013E \u0142 \u0144 \u0146
        \u0148 \u014B \u014D \u014F \u0151 \u0153 \u0155 \u0157 \u0159 \u015B \u015D
        \u015F \u0161 \u0163 \u0165 \u0167 \u0169 \u016B \u016D \u016F \u0171 \u0173
        \u0175 \u0177 \u017A \u017C \u017E \u0180 \u0183 \u0185 \u0188 \u018C-\u018D
        \u0192 \u0195 \u0199-\u019B \u019E \u01A1 \u01A3 \u01A5 \u01A8 \u01AA-\u01AB
        \u01AD \u01B0 \u01B4 \u01B6 \u01B9-\u01BB \u01BD-\u01C3 \u01CE \u01D0 \u01D2
        \u01D4 \u01D6 \u01D8 \u01DA \u01DC-\u01DD \u01DF \u01E1 \u01E3 \u01E5 \u01E7
        \u01E9 \u01EB \u01ED \u01EF-\u01F0 \u01F5 \u01F9 \u01FB \u01FD \u01FF \u0201
        \u0203 \u0205 \u0207 \u0209 \u020B \u020D \u020F \u0211 \u0213 \u0215 \u0217
        \u0219 \u021B \u021D \u021F \u0221 \u0223 \u0225 \u0227 \u0229 \u022B \u022D
        \u022F \u0231 \u0233-\u0239 \u023C \u023F-\u0240 \u0242 \u0247 \u0249 \u024B
        \u024D \u024F-\u02AF \u02B9-\u02C1 \u02C6-\u02D1 \u02EC \u02EE \u0300-\u033F
        \u0342 \u0346-\u034E \u0350-\u036F \u0371 \u0373 \u0375 \u0377 \u037B-\u037D
        \u0390 \u03AC-\u03CE \u03D7 \u03D9 \u03DB \u03DD \u03DF \u03E1 \u03E3 \u03E5
        \u03E7 \u03E9 \u03EB \u03ED \u03EF \u03F3 \u03F8 \u03FB-\u03FC \u0430-\u045F
        \u0461 \u0463 \u0465 \u0467 \u0469 \u046B \u046D \u046F \u0471 \u0473 \u0475
        \u0477 \u0479 \u047B \u047D \u047F \u0481 \u0483-\u0487 \u048B \u048D \u048F
        \u0491 \u0493 \u0495 \u0497 \u0499 \u049B \u049D \u049F \u04A1 \u04A3 \u04A5
        \u04A7 \u04A9 \u04AB \u04AD \u04AF \u04B1 \u04B3 \u04B5 \u04B7 \u04B9 \u04BB
        \u04BD \u04BF \u04C2 \u04C4 \u04C6 \u04C8 \u04CA \u04CC \u04CE-\u04CF \u04D1
        \u04D3 \u04D5 \u04D7 \u04D9 \u04DB \u04DD \u04DF \u04E1 \u04E3 \u04E5 \u04E7
        \u04E9 \u04EB \u04ED \u04EF \u04F1 \u04F3 \u04F5 \u04F7 \u04F9 \u04FB \u04FD
        \u04FF \u0501 \u0503 \u0505 \u0507 \u0509 \u050B \u050D \u050F \u0511 \u0513
        \u0515 \u0517 \u0519 \u051B \u051D \u051F \u0521 \u0523 \u0525 \u0559
        \u0561-\u0586 \u0591-\u05BD \u05BF \u05C1-\u05C2 \u05C4-\u05C5 \u05C7
        \u05D0-\u05EA \u05F0-\u05F2 \u05F3-\u05F4 \u0610-\u061A \u0621-\u063F
        \u0641-\u065E \u0660-\u0669 \u066E-\u0674 \u0679-\u06D3 \u06D5-\u06DC
        \u06DF-\u06E8 \u06EA-\u06EF \u06F0-\u06F9 \u06FA-\u06FF \u0710-\u074A
        \u074D-\u07B1 \u07C0-\u07F5 \u0800-\u082D \u0900-\u0939 \u093C-\u094E
        \u0950-\u0955 \u0960-\u0963 \u0966-\u096F \u0971-\u0972 \u0979-\u097F
        \u0981-\u0983 \u0985-\u098C \u098F-\u0990 \u0993-\u09A8 \u09AA-\u09B0 \u09B2
        \u09B6-\u09B9 \u09BC-\u09C4 \u09C7-\u09C8 \u09CB-\u09CE \u09D7 \u09E0-\u09E3
        \u09E6-\u09F1 \u0A01-\u0A03 \u0A05-\u0A0A \u0A0F-\u0A10 \u0A13-\u0A28
        \u0A2A-\u0A30 \u0A32 \u0A35 \u0A38-\u0A39 \u0A3C \u0A3E-\u0A42 \u0A47-\u0A48
        \u0A4B-\u0A4D \u0A51 \u0A5C \u0A66-\u0A75 \u0A81-\u0A83 \u0A85-\u0A8D
        \u0A8F-\u0A91 \u0A93-\u0AA8 \u0AAA-\u0AB0 \u0AB2-\u0AB3 \u0AB5-\u0AB9
        \u0ABC-\u0AC5 \u0AC7-\u0AC9 \u0ACB-\u0ACD \u0AD0 \u0AE0-\u0AE3 \u0AE6-\u0AEF
        \u0B01-\u0B03 \u0B05-\u0B0C \u0B0F-\u0B10 \u0B13-\u0B28 \u0B2A-\u0B30
        \u0B32-\u0B33 \u0B35-\u0B39 \u0B3C-\u0B44 \u0B47-\u0B48 \u0B4B-\u0B4D
        \u0B56-\u0B57 \u0B5F-\u0B63 \u0B66-\u0B6F \u0B71 \u0B82-\u0B83 \u0B85-\u0B8A
        \u0B8E-\u0B90 \u0B92-\u0B95 \u0B99-\u0B9A \u0B9C \u0B9E-\u0B9F \u0BA3-\u0BA4
        \u0BA8-\u0BAA \u0BAE-\u0BB9 \u0BBE-\u0BC2 \u0BC6-\u0BC8 \u0BCA-\u0BCD \u0BD0
        \u0BD7 \u0BE6-\u0BEF \u0C01-\u0C03 \u0C05-\u0C0C \u0C0E-\u0C10 \u0C12-\u0C28
        \u0C2A-\u0C33 \u0C35-\u0C39 \u0C3D-\u0C44 \u0C46-\u0C48 \u0C4A-\u0C4D
        \u0C55-\u0C56 \u0C58-\u0C59 \u0C60-\u0C63 \u0C66-\u0C6F \u0C82-\u0C83
        \u0C85-\u0C8C \u0C8E-\u0C90 \u0C92-\u0CA8 \u0CAA-\u0CB3 \u0CB5-\u0CB9
        \u0CBC-\u0CC4 \u0CC6-\u0CC8 \u0CCA-\u0CCD \u0CD5-\u0CD6 \u0CDE \u0CE0-\u0CE3
        \u0CE6-\u0CEF \u0D02-\u0D03 \u0D05-\u0D0C \u0D0E-\u0D10 \u0D12-\u0D28
        \u0D2A-\u0D39 \u0D3D-\u0D44 \u0D46-\u0D48 \u0D4A-\u0D4D \u0D57 \u0D60-\u0D63
        \u0D66-\u0D6F \u0D7A-\u0D7F \u0D82-\u0D83 \u0D85-\u0D96 \u0D9A-\u0DB1
        \u0DB3-\u0DBB \u0DBD \u0DC0-\u0DC6 \u0DCA \u0DCF-\u0DD4 \u0DD6 \u0DD8-\u0DDF
        \u0DF2-\u0DF3 \u0E01-\u0E32 \u0E34-\u0E3A \u0E40-\u0E4E \u0E50-\u0E59
        \u0E81-\u0E82 \u0E84 \u0E87-\u0E88 \u0E8A \u0E8D \u0E94-\u0E97 \u0E99-\u0E9F
        \u0EA1-\u0EA3 \u0EA5 \u0EA7 \u0EAA-\u0EAB \u0EAD-\u0EB2 \u0EB4-\u0EB9
        \u0EBB-\u0EBD \u0EC0-\u0EC4 \u0EC6 \u0EC8-\u0ECD \u0ED0-\u0ED9 \u0F00 \u0F0B
        \u0F18-\u0F19 \u0F20-\u0F29 \u0F35 \u0F37 \u0F39 \u0F3E-\u0F42 \u0F44-\u0F47
        \u0F49-\u0F4C \u0F4E-\u0F51 \u0F53-\u0F56 \u0F58-\u0F5B \u0F5D-\u0F68
        \u0F6A-\u0F6C \u0F71-\u0F72 \u0F74 \u0F7A-\u0F80 \u0F82-\u0F84 \u0F86-\u0F8B
        \u0F90-\u0F92 \u0F94-\u0F97 \u0F99-\u0F9C \u0F9E-\u0FA1 \u0FA3-\u0FA6
        \u0FA8-\u0FAB \u0FAD-\u0FB8 \u0FBA-\u0FBC \u0FC6 \u1000-\u1049 \u1050-\u109D
        \u10D0-\u10FA \u1200-\u1248 \u124A-\u124D \u1250-\u1256 \u1258 \u125A-\u125D
        \u1260-\u1288 \u128A-\u128D \u1290-\u12B0 \u12B2-\u12B5 \u12B8-\u12BE \u12C0
        \u12C2-\u12C5 \u12C8-\u12D6 \u12D8-\u1310 \u1312-\u1315 \u1318-\u135A \u135F
        \u1380-\u138F \u13A0-\u13F4 \u1401-\u166C \u166F-\u167F \u1681-\u169A
        \u16A0-\u16EA \u1700-\u170C \u170E-\u1714 \u1720-\u1734 \u1740-\u1753
        \u1760-\u176C \u176E-\u1770 \u1772-\u1773 \u1780-\u17B3 \u17B6-\u17D3 \u17D7
        \u17DC-\u17DD \u17E0-\u17E9 \u1810-\u1819 \u1820-\u1877 \u1880-\u18AA
        \u18B0-\u18F5 \u1900-\u191C \u1920-\u192B \u1930-\u193B \u1946-\u196D
        \u1970-\u1974 \u1980-\u19AB \u19B0-\u19C9 \u19D0-\u19DA \u1A00-\u1A1B
        \u1A20-\u1A5E \u1A60-\u1A7C \u1A7F-\u1A89 \u1A90-\u1A99 \u1AA7 \u1B00-\u1B4B
        \u1B50-\u1B59 \u1B6B-\u1B73 \u1B80-\u1BAA \u1BAE-\u1BB9 \u1C00-\u1C37
        \u1C40-\u1C49 \u1C4D-\u1C7D \u1CD0-\u1CD2 \u1CD4-\u1CF2 \u1D00-\u1D2B \u1D2F
        \u1D3B \u1D4E \u1D6B-\u1D77 \u1D79-\u1D9A \u1DC0-\u1DE6 \u1DFD-\u1DFF \u1E01
        \u1E03 \u1E05 \u1E07 \u1E09 \u1E0B \u1E0D \u1E0F \u1E11 \u1E13 \u1E15 \u1E17
        \u1E19 \u1E1B \u1E1D \u1E1F \u1E21 \u1E23 \u1E25 \u1E27 \u1E29 \u1E2B \u1E2D
        \u1E2F \u1E31 \u1E33 \u1E35 \u1E37 \u1E39 \u1E3B \u1E3D \u1E3F \u1E41 \u1E43
        \u1E45 \u1E47 \u1E49 \u1E4B \u1E4D \u1E4F \u1E51 \u1E53 \u1E55 \u1E57 \u1E59
        \u1E5B \u1E5D \u1E5F \u1E61 \u1E63 \u1E65 \u1E67 \u1E69 \u1E6B \u1E6D \u1E6F
        \u1E71 \u1E73 \u1E75 \u1E77 \u1E79 \u1E7B \u1E7D \u1E7F \u1E81 \u1E83 \u1E85
        \u1E87 \u1E89 \u1E8B \u1E8D \u1E8F \u1E91 \u1E93 \u1E95-\u1E99 \u1E9C-\u1E9D
        \u1E9F \u1EA1 \u1EA3 \u1EA5 \u1EA7 \u1EA9 \u1EAB \u1EAD \u1EAF \u1EB1 \u1EB3
        \u1EB5 \u1EB7 \u1EB9 \u1EBB \u1EBD \u1EBF \u1EC1 \u1EC3 \u1EC5 \u1EC7 \u1EC9
        \u1ECB \u1ECD \u1ECF \u1ED1 \u1ED3 \u1ED5 \u1ED7 \u1ED9 \u1EDB \u1EDD \u1EDF
        \u1EE1 \u1EE3 \u1EE5 \u1EE7 \u1EE9 \u1EEB \u1EED \u1EEF \u1EF1 \u1EF3 \u1EF5
        \u1EF7 \u1EF9 \u1EFB \u1EFD \u1EFF-\u1F07 \u1F10-\u1F15 \u1F20-\u1F27
        \u1F30-\u1F37 \u1F40-\u1F45 \u1F50-\u1F57 \u1F60-\u1F67 \u1F70 \u1F72 \u1F74
        \u1F76 \u1F78 \u1F7A \u1F7C \u1FB0-\u1FB1 \u1FB6 \u1FC6 \u1FD0-\u1FD2
        \u1FD6-\u1FD7 \u1FE0-\u1FE2 \u1FE4-\u1FE7 \u1FF6 \u200C-\u200D \u214E \u2184
        \u2C30-\u2C5E \u2C61 \u2C65-\u2C66 \u2C68 \u2C6A \u2C6C \u2C71 \u2C73-\u2C74
        \u2C76-\u2C7B \u2C81 \u2C83 \u2C85 \u2C87 \u2C89 \u2C8B \u2C8D \u2C8F \u2C91
        \u2C93 \u2C95 \u2C97 \u2C99 \u2C9B \u2C9D \u2C9F \u2CA1 \u2CA3 \u2CA5 \u2CA7
        \u2CA9 \u2CAB \u2CAD \u2CAF \u2CB1 \u2CB3 \u2CB5 \u2CB7 \u2CB9 \u2CBB \u2CBD
        \u2CBF \u2CC1 \u2CC3 \u2CC5 \u2CC7 \u2CC9 \u2CCB \u2CCD \u2CCF \u2CD1 \u2CD3
        \u2CD5 \u2CD7 \u2CD9 \u2CDB \u2CDD \u2CDF \u2CE1 \u2CE3-\u2CE4 \u2CEC
        \u2CEE-\u2CF1 \u2D00-\u2D25 \u2D30-\u2D65 \u2D80-\u2D96 \u2DA0-\u2DA6
        \u2DA8-\u2DAE \u2DB0-\u2DB6 \u2DB8-\u2DBE \u2DC0-\u2DC6 \u2DC8-\u2DCE
        \u2DD0-\u2DD6 \u2DD8-\u2DDE \u2DE0-\u2DFF \u2E2F \u3005-\u3007 \u302A-\u302D
        \u303C \u3041-\u3096 \u3099-\u309A \u309D-\u309E \u30A1-\u30FA \u30FB
        \u30FC-\u30FE \u3105-\u312D \u31A0-\u31B7 \u31F0-\u31FF \u3400-\u4DB5
        \u4E00-\u9FCB \uA000-\uA48C \uA4D0-\uA4FD \uA500-\uA60C \uA610-\uA62B \uA641
        \uA643 \uA645 \uA647 \uA649 \uA64B \uA64D \uA64F \uA651 \uA653 \uA655 \uA657
        \uA659 \uA65B \uA65D \uA65F \uA663 \uA665 \uA667 \uA669 \uA66B \uA66D-\uA66F
        \uA67C-\uA67D \uA67F \uA681 \uA683 \uA685 \uA687 \uA689 \uA68B \uA68D \uA68F
        \uA691 \uA693 \uA695 \uA697 \uA6A0-\uA6E5 \uA6F0-\uA6F1 \uA717-\uA71F \uA723
        \uA725 \uA727 \uA729 \uA72B \uA72D \uA72F-\uA731 \uA733 \uA735 \uA737 \uA739
        \uA73B \uA73D \uA73F \uA741 \uA743 \uA745 \uA747 \uA749 \uA74B \uA74D \uA74F
        \uA751 \uA753 \uA755 \uA757 \uA759 \uA75B \uA75D \uA75F \uA761 \uA763 \uA765
        \uA767 \uA769 \uA76B \uA76D \uA76F \uA771-\uA778 \uA77A \uA77C \uA77F \uA781
        \uA783 \uA785 \uA787-\uA788 \uA78C \uA7FB-\uA827 \uA840-\uA873 \uA880-\uA8C4
        \uA8D0-\uA8D9 \uA8E0-\uA8F7 \uA8FB \uA900-\uA92D \uA930-\uA953 \uA980-\uA9C0
        \uA9CF-\uA9D9 \uAA00-\uAA36 \uAA40-\uAA4D \uAA50-\uAA59 \uAA60-\uAA76
        \uAA7A-\uAA7B \uAA80-\uAAC2 \uAADB-\uAADD \uABC0-\uABEA \uABEC-\uABED
        \uABF0-\uABF9 \uAC00-\uD7A3 \uFA0E-\uFA0F \uFA11 \uFA13-\uFA14 \uFA1F \uFA21
        \uFA23-\uFA24 \uFA27-\uFA29 \uFB1E \uFE20-\uFE26 \uFE73 \U00010000-\U0001000B
        \U0001000D-\U00010026 \U00010028-\U0001003A \U0001003C-\U0001003D
        \U0001003F-\U0001004D \U00010050-\U0001005D \U00010080-\U000100FA \U000101FD
        \U00010280-\U0001029C \U000102A0-\U000102D0 \U00010300-\U0001031E
        \U00010330-\U00010340 \U00010342-\U00010349 \U00010380-\U0001039D
        \U000103A0-\U000103C3 \U000103C8-\U000103CF \U00010428-\U0001049D
        \U000104A0-\U000104A9 \U00010800-\U00010805 \U00010808 \U0001080A-\U00010835
        \U00010837-\U00010838 \U0001083C \U0001083F-\U00010855 \U00010900-\U00010915
        \U00010920-\U00010939 \U00010A00-\U00010A03 \U00010A05-\U00010A06
        \U00010A0C-\U00010A13 \U00010A15-\U00010A17 \U00010A19-\U00010A33
        \U00010A38-\U00010A3A \U00010A3F \U00010A60-\U00010A7C \U00010B00-\U00010B35
        \U00010B40-\U00010B55 \U00010B60-\U00010B72 \U00010C00-\U00010C48
        \U00011080-\U000110BA \U00012000-\U0001236E \U00013000-\U0001342E
        \U00020000-\U0002A6D6 \U0002A700-\U0002B734
    """.replace(
        " ", ""
    ).replace(
        "\n", ""
    )
)

# these are the ASCII characters as per IDNA
BYTES_CHAR: Final = rb"\x2D\x30-\x39\x61-\x7A"

# these are a reasonably complete subset of the valid/registered TLDs, both as punycode
# and unicode codepoints where relevant
STR_TLD: Final = r"""
    (?:xn--vermgensberatung-pwb|xn--vermgensberater-ctb|xn--clchc0ea0b2g2a9gcd
        |xn--w4r85el8fhu5dnra|northwesternmutual|travelersinsurance
        |verm\u00f6gensberatung|xn--3oq18vl8pn36a|xn--5su34j936bgsg
        |xn--bck1b9a5dre4c|xn--mgbai9azgqp6j|xn--mgberp4a5d4ar
        |xn--xkc2dl3a5ee0h|verm\u00f6gensberater|xn--fzys8d69uvgm
        |xn--mgba7c0bbn0a|xn--xkc2al3hye2a|americanexpress|kerryproperties
        |sandvikcoromant|xn--i1b6b1a6a2e|xn--kcrx77d1x4a|xn--lgbbat1ad8j
        |xn--mgba3a4f16a|xn--mgbaakc7dvf|xn--mgbc0a9azcg|xn--nqv7fs00ema
        |afamilycompany|americanfamily|bananarepublic|cancerresearch
        |cookingchannel|kerrylogistics|weatherchannel|xn--54b7fta0cc
        |xn--6qq986b3xl|xn--80aqecdr1a|xn--b4w605ferd|xn--fiq228c5hs
        |xn--h2breg3eve|xn--jlq61u9w7b|xn--mgba3a3ejt|xn--mgbaam7a8h
        |xn--mgbayh7gpa|xn--mgbb9fbpob|xn--mgbbh1a71e|xn--mgbca7dzdo
        |xn--mgbi4ecexp|xn--mgbx4cd0ab|xn--rvc1e0am3e|international
        |lifeinsurance|spreadbetting|travelchannel|wolterskluwer|xn--eckvdtc9d
        |xn--fpcrj9c3d|xn--fzc2c9e2c|xn--h2brj9c8c|xn--tiq49xqyj|xn--yfro4i67o
        |xn--ygbi2ammx|construction|lplfinancial|scholarships|versicherung
        |xn--3e0b707e|xn--45br5cyl|xn--80adxhks|xn--80asehdb|xn--8y0a063a
        |xn--gckr3f0f|xn--mgb9awbf|xn--mgbab2bd|xn--mgbgu82a|xn--mgbpl2fh
        |xn--mgbt3dhd|xn--mk1bu44c|xn--ngbc5azd|xn--ngbe9e0a|xn--ogbpf8fl
        |xn--qcka1pmc|accountants|barclaycard|blackfriday|blockbuster
        |bridgestone|calvinklein|contractors|creditunion|engineering
        |enterprises|foodnetwork|investments|kerryhotels|lamborghini
        |motorcycles|olayangroup|photography|playstation|productions
        |progressive|redumbrella|rightathome|williamhill|xn--11b4c3d
        |xn--1ck2e1b|xn--1qqw23a|xn--2scrj9c|xn--3bst00m|xn--3ds443g
        |xn--3hcrj9c|xn--42c2d9a|xn--45brj9c|xn--55qw42g|xn--6frz82g
        |xn--80ao21a|xn--9krt00a|xn--cck2b3b|xn--czr694b|xn--d1acj3b
        |xn--efvy88h|xn--estv75g|xn--fct429k|xn--fjq720a|xn--flw351e
        |xn--g2xx48c|xn--gecrj9c|xn--gk3at1e|xn--h2brj9c|xn--hxt814e
        |xn--imr513n|xn--j6w193g|xn--jvr189m|xn--kprw13d|xn--kpry57d
        |xn--kpu716f|xn--mgbbh1a|xn--mgbtx2b|xn--mix891f|xn--nyqy26a
        |xn--otu796d|xn--pbt977c|xn--pgbs0dh|xn--q9jyb4c|xn--rhqv96g
        |xn--rovu88b|xn--s9brj9c|xn--ses554g|xn--t60b56a|xn--vuq861b
        |xn--w4rs40l|xn--xhq521b|xn--zfr164b
        |\u0b9a\u0bbf\u0b99\u0bcd\u0b95\u0baa\u0bcd\u0baa\u0bc2\u0bb0\u0bcd
        |accountant|apartments|associates|basketball|bnpparibas|boehringer
        |capitalone|consulting|creditcard|cuisinella|eurovision|extraspace
        |foundation|healthcare|immobilien|industries|management|mitsubishi
        |nationwide|newholland|nextdirect|onyourside|properties|protection
        |prudential|realestate|republican|restaurant|schaeffler|swiftcover
        |tatamotors|technology|telefonica|university|vistaprint|vlaanderen
        |volkswagen|xn--30rr7y|xn--3pxu8k|xn--45q11c|xn--4gbrim|xn--55qx5d
        |xn--5tzm5g|xn--80aswg|xn--90a3ac|xn--9dbq2a|xn--9et52u|xn--c2br7g
        |xn--cg4bki|xn--czrs0t|xn--czru2d|xn--fiq64b|xn--fiqs8s|xn--fiqz9s
        |xn--io0a7i|xn--kput3i|xn--mxtq1m|xn--o3cw4h|xn--pssy2u|xn--unup4y
        |xn--wgbh1c|xn--wgbl6a|xn--y9a3aq|accenture|alfaromeo|allfinanz
        |amsterdam|analytics|aquarelle|barcelona|bloomberg|christmas|community
        |directory|education|equipment|fairwinds|financial|firestone|fresenius
        |frontdoor|fujixerox|furniture|goldpoint|goodhands|hisamitsu|homedepot
        |homegoods|homesense|honeywell|institute|insurance|kuokgroup|ladbrokes
        |lancaster|landrover|lifestyle|marketing|marshalls|melbourne|microsoft
        |panasonic|passagens|pramerica|richardli|scjohnson|shangrila|solutions
        |statebank|statefarm|stockholm|travelers|vacations|xn--90ais|xn--c1avg
        |xn--d1alf|xn--e1a4c|xn--fhbei|xn--j1aef|xn--j1amh|xn--l1acc|xn--ngbrx
        |xn--nqv7f|xn--p1acf|xn--tckwe|xn--vhquv|yodobashi|abudhabi|airforce
        |allstate|attorney|barclays|barefoot|bargains|baseball|boutique
        |bradesco|broadway|brussels|budapest|builders|business|capetown
        |catering|catholic|chrysler|cipriani|cityeats|cleaning|clinique
        |clothing|commbank|computer|delivery|deloitte|democrat|diamonds
        |discount|discover|download|engineer|ericsson|esurance|etisalat
        |everbank|exchange|feedback|fidelity|firmdale|football|frontier
        |goodyear|grainger|graphics|guardian|hdfcbank|helsinki|holdings
        |hospital|infiniti|ipiranga|istanbul|jpmorgan|lighting|lundbeck
        |marriott|maserati|mckinsey|memorial|merckmsd|mortgage|movistar
        |observer|partners|pharmacy|pictures|plumbing|property|redstone
        |reliance|saarland|samsclub|security|services|shopping|showtime
        |softbank|software|stcgroup|supplies|symantec|training|uconnect
        |vanguard|ventures|verisign|woodside|xn--90ae|xn--node|xn--p1ai
        |xn--qxam|yokohama|\u0627\u0644\u0633\u0639\u0648\u062f\u064a\u0629
        |abogado|academy|agakhan|alibaba|android|athleta|auction|audible
        |auspost|avianca|banamex|bauhaus|bentley|bestbuy|booking|brother
        |bugatti|capital|caravan|careers|cartier|channel|charity|chintai
        |citadel|clubmed|college|cologne|comcast|company|compare|contact
        |cooking|corsica|country|coupons|courses|cricket|cruises|dentist
        |digital|domains|exposed|express|farmers|fashion|ferrari|ferrero
        |finance|fishing|fitness|flights|florist|flowers|forsale|frogans
        |fujitsu|gallery|genting|godaddy|grocery|guitars|hamburg|hangout
        |hitachi|holiday|hosting|hoteles|hotmail|hyundai|iselect|ismaili
        |jewelry|juniper|kitchen|komatsu|lacaixa|lancome|lanxess|lasalle
        |latrobe|leclerc|liaison|limited|lincoln|markets|metlife|monster
        |netbank|netflix|network|neustar|okinawa|oldnavy|organic|origins
        |panerai|philips|pioneer|politie|realtor|recipes|rentals|reviews
        |rexroth|samsung|sandvik|schmidt|schwarz|science|shiksha|shriram
        |singles|spiegel|staples|starhub|statoil|storage|support|surgery
        |systems|temasek|theater|theatre|tickets|tiffany|toshiba|trading
        |walmart|wanggou|watches|weather|website|wedding|whoswho|windows
        |winners|xfinity|yamaxun|youtube|zuerich
        |\u043a\u0430\u0442\u043e\u043b\u0438\u043a
        |\u0627\u062a\u0635\u0627\u0644\u0627\u062a
        |\u0627\u0644\u062c\u0632\u0627\u0626\u0631
        |\u0627\u0644\u0639\u0644\u064a\u0627\u0646
        |\u0643\u0627\u062b\u0648\u0644\u064a\u0643
        |\u0645\u0648\u0628\u0627\u064a\u0644\u064a
        |\u067e\u0627\u06a9\u0633\u062a\u0627\u0646
        |\u0b87\u0ba8\u0bcd\u0ba4\u0bbf\u0baf\u0bbe|abarth|abbott|abbvie|active
        |africa|agency|airbus|airtel|alipay|alsace|alstom|anquan|aramco|author
        |bayern|beauty|berlin|bharti|blanco|bostik|boston|broker|camera|career
        |caseih|casino|center|chanel|chrome|church|circle|claims|clinic|coffee
        |comsec|condos|coupon|credit|cruise|dating|datsun|dealer|degree|dental
        |design|direct|doctor|dunlop|dupont|durban|emerck|energy|estate|events
        |expert|family|flickr|futbol|gallup|garden|george|giving|global|google
        |gratis|health|hermes|hiphop|hockey|hotels|hughes|imamat|insure|intuit
        |jaguar|joburg|juegos|kaufen|kinder|kindle|kosher|lancia|latino|lawyer
        |lefrak|living|locker|london|luxury|madrid|maison|makeup|market|mattel
        |mobile|mobily|monash|mormon|moscow|museum|mutual|nagoya|natura|nissan
        |nissay|norton|nowruz|office|olayan|online|oracle|orange|otsuka|pfizer
        |photos|physio|piaget|pictet|quebec|racing|realty|reisen|repair|report
        |review|rocher|rogers|ryukyu|safety|sakura|sanofi|school|schule|search
        |secure|select|shouji|soccer|social|stream|studio|supply|suzuki|swatch
        |sydney|taipei|taobao|target|tattoo|tennis|tienda|tjmaxx|tkmaxx|toyota
        |travel|unicom|viajes|viking|villas|virgin|vision|voting|voyage|vuelos
        |walter|warman|webcam|xihuan|yachts|yandex|zappos
        |\u043c\u043e\u0441\u043a\u0432\u0430
        |\u043e\u043d\u043b\u0430\u0439\u043d
        |\u0627\u0628\u0648\u0638\u0628\u064a
        |\u0627\u0631\u0627\u0645\u0643\u0648
        |\u0627\u0644\u0627\u0631\u062f\u0646
        |\u0627\u0644\u0645\u063a\u0631\u0628
        |\u0627\u0645\u0627\u0631\u0627\u062a
        |\u0641\u0644\u0633\u0637\u064a\u0646
        |\u0645\u0644\u064a\u0633\u064a\u0627
        |\u092d\u093e\u0930\u0924\u092e\u094d
        |\u0b87\u0bb2\u0b99\u0bcd\u0b95\u0bc8
        |\u30d5\u30a1\u30c3\u30b7\u30e7\u30f3|actor|adult|aetna|amfam|amica
        |apple|archi|audio|autos|azure|baidu|beats|bible|bingo|black|boats
        |bosch|build|canon|cards|chase|cheap|cisco|citic|click|cloud|coach
        |codes|crown|cymru|dabur|dance|deals|delta|dodge|drive|dubai|earth
        |edeka|email|epost|epson|faith|fedex|final|forex|forum|gallo|games
        |gifts|gives|glade|glass|globo|gmail|green|gripe|group|gucci|guide
        |homes|honda|horse|house|hyatt|ikano|intel|irish|iveco|jetzt|koeln
        |kyoto|lamer|lease|legal|lexus|lilly|linde|lipsy|lixil|loans|locus
        |lotte|lotto|lupin|macys|mango|media|miami|money|mopar|movie|nadex
        |nexus|nikon|ninja|nokia|nowtv|omega|osaka|paris|parts|party|phone
        |photo|pizza|place|poker|praxi|press|prime|promo|quest|radio|rehab
        |reise|ricoh|rocks|rodeo|rugby|salon|sener|seven|sharp|shell|shoes
        |skype|sling|smart|smile|solar|space|sport|stada|store|study|style
        |sucks|swiss|tatar|tires|tirol|tmall|today|tokyo|tools|toray|total
        |tours|trade|trust|tunes|tushu|ubank|vegas|video|vodka|volvo|wales
        |watch|weber|weibo|works|world|xerox|yahoo|zippo
        |\u0627\u06cc\u0631\u0627\u0646|\u0628\u0627\u0632\u0627\u0631
        |\u0628\u06be\u0627\u0631\u062a|\u0633\u0648\u062f\u0627\u0646
        |\u0633\u0648\u0631\u064a\u0629|\u0647\u0645\u0631\u0627\u0647
        |\u092d\u093e\u0930\u094b\u0924|\u0938\u0902\u0917\u0920\u0928
        |\u09ac\u09be\u0982\u09b2\u09be|\u0c2d\u0c3e\u0c30\u0c24\u0c4d
        |\u0d2d\u0d3e\u0d30\u0d24\u0d02|\u5609\u91cc\u5927\u9152\u5e97|aarp
        |able|adac|aero|aigo|akdn|ally|amex|arab|army|arpa|arte|asda|asia|audi
        |auto|baby|band|bank|bbva|beer|best|bike|bing|blog|blue|bofa|bond|book
        |buzz|cafe|call|camp|care|cars|casa|case|cash|cbre|cern|chat|citi|city
        |club|cool|coop|cyou|data|date|dclk|deal|dell|desi|diet|dish|docs|doha
        |duck|duns|dvag|erni|fage|fail|fans|farm|fast|fiat|fido|film|fire|fish
        |flir|food|ford|free|fund|game|gbiz|gent|ggee|gift|gmbh|gold|golf|goog
        |guge|guru|hair|haus|hdfc|help|here|hgtv|host|hsbc|icbc|ieee|imdb|immo
        |info|itau|java|jeep|jobs|jprs|kddi|kiwi|kpmg|kred|land|lego|lgbt|lidl
        |life|like|limo|link|live|loan|loft|love|ltda|luxe|maif|meet|meme|menu
        |mini|mint|mobi|moda|moto|name|navy|news|next|nico|nike|ollo|open|page
        |pars|pccw|pics|ping|pink|play|plus|pohl|porn|post|prod|prof|qpon|raid
        |read|reit|rent|rest|rich|rmit|room|rsvp|ruhr|safe|sale|sarl|save|saxo
        |scor|scot|seat|seek|sexy|shaw|shia|shop|show|silk|sina|site|skin|sncf
        |sohu|song|sony|spot|star|surf|talk|taxi|team|tech|teva|tiaa|tips|town
        |toys|tube|vana|visa|viva|vivo|vote|voto|wang|weir|wien|wiki|wine|work
        |xbox|yoga|zara|zero|zone|\u0434\u0435\u0442\u0438
        |\u0441\u0430\u0439\u0442|\u0628\u0627\u0631\u062a
        |\u0628\u064a\u062a\u0643|\u062a\u0648\u0646\u0633
        |\u0634\u0628\u0643\u0629|\u0639\u0631\u0627\u0642
        |\u0639\u0645\u0627\u0646|\u0645\u0648\u0642\u0639
        |\u0680\u0627\u0631\u062a|\u092d\u093e\u0930\u0924
        |\u09ad\u09be\u09b0\u09a4|\u09ad\u09be\u09f0\u09a4
        |\u0a2d\u0a3e\u0a30\u0a24|\u0aad\u0abe\u0ab0\u0aa4
        |\u0b2d\u0b3e\u0b30\u0b24|\u0cad\u0cbe\u0cb0\u0ca4
        |\u0dbd\u0d82\u0d9a\u0dcf|\u30af\u30e9\u30a6\u30c9
        |\u30b0\u30fc\u30b0\u30eb|\u30dd\u30a4\u30f3\u30c8
        |\u5927\u4f17\u6c7d\u8f66|\u7ec4\u7ec7\u673a\u6784
        |\u96fb\u8a0a\u76c8\u79d1|\u9999\u683c\u91cc\u62c9|aaa|abb|abc|aco|ads
        |aeg|afl|aig|anz|aol|app|art|aws|axa|bar|bbc|bbt|bcg|bcn|bet|bid|bio
        |biz|bms|bmw|bnl|bom|boo|bot|box|buy|bzh|cab|cal|cam|car|cat|cba|cbn
        |cbs|ceb|ceo|cfa|cfd|com|crs|csc|dad|day|dds|dev|dhl|diy|dnp|dog|dot
        |dtv|dvr|eat|eco|edu|esq|eus|fan|fit|fly|foo|fox|frl|ftr|fun|fyi|gal
        |gap|gdn|gea|gle|gmo|gmx|goo|gop|got|gov|hbo|hiv|hkt|hot|how|ibm|ice
        |icu|ifm|inc|ing|ink|int|ist|itv|jcb|jcp|jio|jlc|jll|jmp|jnj|jot|joy
        |kfh|kia|kim|kpn|krd|lat|law|lds|llc|lol|lpl|ltd|man|map|mba|med|men
        |mil|mit|mlb|mls|mma|moe|moi|mom|mov|msd|mtn|mtr|nab|nba|nec|net|new
        |nfl|ngo|nhk|now|nra|nrw|ntt|nyc|obi|off|one|ong|onl|ooo|org|ott|ovh
        |pay|pet|phd|pid|pin|pnc|pro|pru|pub|pwc|qvc|red|ren|ril|rio|rip|run
        |rwe|sap|sas|sbi|sbs|sca|scb|ses|sew|sex|sfr|ski|sky|soy|srl|srt|stc
        |tab|tax|tci|tdk|tel|thd|tjx|top|trv|tui|tvs|ubs|uno|uol|ups|vet|vig
        |vin|vip|wed|win|wme|wow|wtc|wtf|xin|xxx|xyz|you|yun|zip
        |\u0431\u0435\u043b|\u043a\u043e\u043c|\u043c\u043a\u0434
        |\u043c\u043e\u043d|\u043e\u0440\u0433|\u0440\u0443\u0441
        |\u0441\u0440\u0431|\u0443\u043a\u0440|\u049b\u0430\u0437
        |\u0570\u0561\u0575|\u05e7\u05d5\u05dd|\u0639\u0631\u0628
        |\u0642\u0637\u0631|\u0643\u0648\u0645|\u0645\u0635\u0631
        |\u0915\u0949\u092e|\u0928\u0947\u091f|\u0e04\u0e2d\u0e21
        |\u0e44\u0e17\u0e22|\u307f\u3093\u306a|\u30b9\u30c8\u30a2
        |\u30bb\u30fc\u30eb|\u4e2d\u6587\u7f51|\u5929\u4e3b\u6559
        |\u6211\u7231\u4f60|\u65b0\u52a0\u5761|\u6de1\u9a6c\u9521
        |\u8bfa\u57fa\u4e9a|\u98de\u5229\u6d66|ac|ad|ae|af|ag|ai|al|am|ao|aq|ar
        |as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw
        |by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj
        |dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg
        |gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im
        |in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb
        |lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr
        |ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe
        |pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se
        |sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk
        |tl|tm|tn|to|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf
        |ws|ye|yt|za|zm|zw|\u03b5\u03bb|\u0431\u0433|\u0435\u044e|\u0440\u0444
        |\u10d2\u10d4|\u30b3\u30e0|\u4e16\u754c|\u4e2d\u4fe1|\u4e2d\u56fd
        |\u4e2d\u570b|\u4f01\u4e1a|\u4f5b\u5c71|\u4fe1\u606f|\u5065\u5eb7
        |\u516b\u5366|\u516c\u53f8|\u516c\u76ca|\u53f0\u6e7e|\u53f0\u7063
        |\u5546\u57ce|\u5546\u5e97|\u5546\u6807|\u5609\u91cc|\u5728\u7ebf
        |\u5927\u62ff|\u5a31\u4e50|\u5bb6\u96fb|\u5de5\u884c|\u5e7f\u4e1c
        |\u5fae\u535a|\u6148\u5584|\u624b\u673a|\u624b\u8868|\u62db\u8058
        |\u653f\u52a1|\u653f\u5e9c|\u65b0\u95fb|\u65f6\u5c1a|\u66f8\u7c4d
        |\u673a\u6784|\u6e38\u620f|\u6fb3\u9580|\u70b9\u770b|\u73e0\u5b9d
        |\u79fb\u52a8|\u7f51\u5740|\u7f51\u5e97|\u7f51\u7ad9|\u7f51\u7edc
        |\u8054\u901a|\u8c37\u6b4c|\u8d2d\u7269|\u901a\u8ca9|\u96c6\u56e2
        |\u98df\u54c1|\u9910\u5385|\u9999\u6e2f|\ub2f7\ub137|\ub2f7\ucef4
        |\uc0bc\uc131|\ud55c\uad6d)
"""

# these are a reasonably complete subset of the valid/registered TLDs, both as punycode
# and unicode codepoints where relevant
BYTES_TLD: Final = rb"""
    (?:xn--vermgensberatung-pwb|xn--vermgensberater-ctb|xn--clchc0ea0b2g2a9gcd
        |xn--w4r85el8fhu5dnra|northwesternmutual|travelersinsurance|xn--3oq18vl8pn36a
        |xn--5su34j936bgsg|xn--bck1b9a5dre4c|xn--mgbai9azgqp6j|xn--mgberp4a5d4ar
        |xn--xkc2dl3a5ee0h|xn--fzys8d69uvgm|xn--mgba7c0bbn0a|xn--xkc2al3hye2a
        |americanexpress|kerryproperties|sandvikcoromant|xn--i1b6b1a6a2e
        |xn--kcrx77d1x4a|xn--lgbbat1ad8j|xn--mgba3a4f16a|xn--mgbaakc7dvf
        |xn--mgbc0a9azcg|xn--nqv7fs00ema|afamilycompany|americanfamily|bananarepublic
        |cancerresearch|cookingchannel|kerrylogistics|weatherchannel|xn--54b7fta0cc
        |xn--6qq986b3xl|xn--80aqecdr1a|xn--b4w605ferd|xn--fiq228c5hs|xn--h2breg3eve
        |xn--jlq61u9w7b|xn--mgba3a3ejt|xn--mgbaam7a8h|xn--mgbayh7gpa|xn--mgbb9fbpob
        |xn--mgbbh1a71e|xn--mgbca7dzdo|xn--mgbi4ecexp|xn--mgbx4cd0ab|xn--rvc1e0am3e
        |international|lifeinsurance|spreadbetting|travelchannel|wolterskluwer
        |xn--eckvdtc9d|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--h2brj9c8c|xn--tiq49xqyj
        |xn--yfro4i67o|xn--ygbi2ammx|construction|lplfinancial|scholarships|versicherung
        |xn--3e0b707e|xn--45br5cyl|xn--80adxhks|xn--80asehdb|xn--8y0a063a|xn--gckr3f0f
        |xn--mgb9awbf|xn--mgbab2bd|xn--mgbgu82a|xn--mgbpl2fh|xn--mgbt3dhd|xn--mk1bu44c
        |xn--ngbc5azd|xn--ngbe9e0a|xn--ogbpf8fl|xn--qcka1pmc|accountants|barclaycard
        |blackfriday|blockbuster|bridgestone|calvinklein|contractors|creditunion
        |engineering|enterprises|foodnetwork|investments|kerryhotels|lamborghini
        |motorcycles|olayangroup|photography|playstation|productions|progressive
        |redumbrella|rightathome|williamhill|xn--11b4c3d|xn--1ck2e1b|xn--1qqw23a
        |xn--2scrj9c|xn--3bst00m|xn--3ds443g|xn--3hcrj9c|xn--42c2d9a|xn--45brj9c
        |xn--55qw42g|xn--6frz82g|xn--80ao21a|xn--9krt00a|xn--cck2b3b|xn--czr694b
        |xn--d1acj3b|xn--efvy88h|xn--estv75g|xn--fct429k|xn--fjq720a|xn--flw351e
        |xn--g2xx48c|xn--gecrj9c|xn--gk3at1e|xn--h2brj9c|xn--hxt814e|xn--imr513n
        |xn--j6w193g|xn--jvr189m|xn--kprw13d|xn--kpry57d|xn--kpu716f|xn--mgbbh1a
        |xn--mgbtx2b|xn--mix891f|xn--nyqy26a|xn--otu796d|xn--pbt977c|xn--pgbs0dh
        |xn--q9jyb4c|xn--rhqv96g|xn--rovu88b|xn--s9brj9c|xn--ses554g|xn--t60b56a
        |xn--vuq861b|xn--w4rs40l|xn--xhq521b|xn--zfr164b|accountant|apartments
        |associates|basketball|bnpparibas|boehringer|capitalone|consulting|creditcard
        |cuisinella|eurovision|extraspace|foundation|healthcare|immobilien|industries
        |management|mitsubishi|nationwide|newholland|nextdirect|onyourside|properties
        |protection|prudential|realestate|republican|restaurant|schaeffler|swiftcover
        |tatamotors|technology|telefonica|university|vistaprint|vlaanderen|volkswagen
        |xn--30rr7y|xn--3pxu8k|xn--45q11c|xn--4gbrim|xn--55qx5d|xn--5tzm5g|xn--80aswg
        |xn--90a3ac|xn--9dbq2a|xn--9et52u|xn--c2br7g|xn--cg4bki|xn--czrs0t|xn--czru2d
        |xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--io0a7i|xn--kput3i|xn--mxtq1m|xn--o3cw4h
        |xn--pssy2u|xn--unup4y|xn--wgbh1c|xn--wgbl6a|xn--y9a3aq|accenture|alfaromeo
        |allfinanz|amsterdam|analytics|aquarelle|barcelona|bloomberg|christmas|community
        |directory|education|equipment|fairwinds|financial|firestone|fresenius|frontdoor
        |fujixerox|furniture|goldpoint|goodhands|hisamitsu|homedepot|homegoods|homesense
        |honeywell|institute|insurance|kuokgroup|ladbrokes|lancaster|landrover
        |lifestyle|marketing|marshalls|melbourne|microsoft|panasonic|passagens
        |pramerica|richardli|scjohnson|shangrila|solutions|statebank|statefarm
        |stockholm|travelers|vacations|xn--90ais|xn--c1avg|xn--d1alf|xn--e1a4c
        |xn--fhbei|xn--j1aef|xn--j1amh|xn--l1acc|xn--ngbrx|xn--nqv7f|xn--p1acf
        |xn--tckwe|xn--vhquv|yodobashi|abudhabi|airforce|allstate|attorney|barclays
        |barefoot|bargains|baseball|boutique|bradesco|broadway|brussels|budapest
        |builders|business|capetown|catering|catholic|chrysler|cipriani|cityeats
        |cleaning|clinique|clothing|commbank|computer|delivery|deloitte|democrat
        |diamonds|discount|discover|download|engineer|ericsson|esurance|etisalat
        |everbank|exchange|feedback|fidelity|firmdale|football|frontier|goodyear
        |grainger|graphics|guardian|hdfcbank|helsinki|holdings|hospital|infiniti
        |ipiranga|istanbul|jpmorgan|lighting|lundbeck|marriott|maserati|mckinsey
        |memorial|merckmsd|mortgage|movistar|observer|partners|pharmacy|pictures
        |plumbing|property|redstone|reliance|saarland|samsclub|security|services
        |shopping|showtime|softbank|software|stcgroup|supplies|symantec|training
        |uconnect|vanguard|ventures|verisign|woodside|xn--90ae|xn--node|xn--p1ai
        |xn--qxam|yokohama|abogado|academy|agakhan|alibaba|android|athleta|auction
        |audible|auspost|avianca|banamex|bauhaus|bentley|bestbuy|booking|brother|bugatti
        |capital|caravan|careers|cartier|channel|charity|chintai|citadel|clubmed|college
        |cologne|comcast|company|compare|contact|cooking|corsica|country|coupons|courses
        |cricket|cruises|dentist|digital|domains|exposed|express|farmers|fashion|ferrari
        |ferrero|finance|fishing|fitness|flights|florist|flowers|forsale|frogans|fujitsu
        |gallery|genting|godaddy|grocery|guitars|hamburg|hangout|hitachi|holiday|hosting
        |hoteles|hotmail|hyundai|iselect|ismaili|jewelry|juniper|kitchen|komatsu|lacaixa
        |lancome|lanxess|lasalle|latrobe|leclerc|liaison|limited|lincoln|markets|metlife
        |monster|netbank|netflix|network|neustar|okinawa|oldnavy|organic|origins|panerai
        |philips|pioneer|politie|realtor|recipes|rentals|reviews|rexroth|samsung|sandvik
        |schmidt|schwarz|science|shiksha|shriram|singles|spiegel|staples|starhub|statoil
        |storage|support|surgery|systems|temasek|theater|theatre|tickets|tiffany|toshiba
        |trading|walmart|wanggou|watches|weather|website|wedding|whoswho|windows|winners
        |xfinity|yamaxun|youtube|zuerich|abarth|abbott|abbvie|active|africa|agency
        |airbus|airtel|alipay|alsace|alstom|anquan|aramco|author|bayern|beauty|berlin
        |bharti|blanco|bostik|boston|broker|camera|career|caseih|casino|center|chanel
        |chrome|church|circle|claims|clinic|coffee|comsec|condos|coupon|credit|cruise
        |dating|datsun|dealer|degree|dental|design|direct|doctor|dunlop|dupont|durban
        |emerck|energy|estate|events|expert|family|flickr|futbol|gallup|garden|george
        |giving|global|google|gratis|health|hermes|hiphop|hockey|hotels|hughes|imamat
        |insure|intuit|jaguar|joburg|juegos|kaufen|kinder|kindle|kosher|lancia|latino
        |lawyer|lefrak|living|locker|london|luxury|madrid|maison|makeup|market|mattel
        |mobile|mobily|monash|mormon|moscow|museum|mutual|nagoya|natura|nissan|nissay
        |norton|nowruz|office|olayan|online|oracle|orange|otsuka|pfizer|photos|physio
        |piaget|pictet|quebec|racing|realty|reisen|repair|report|review|rocher|rogers
        |ryukyu|safety|sakura|sanofi|school|schule|search|secure|select|shouji|soccer
        |social|stream|studio|supply|suzuki|swatch|sydney|taipei|taobao|target|tattoo
        |tennis|tienda|tjmaxx|tkmaxx|toyota|travel|unicom|viajes|viking|villas|virgin
        |vision|voting|voyage|vuelos|walter|warman|webcam|xihuan|yachts|yandex|zappos
        |actor|adult|aetna|amfam|amica|apple|archi|audio|autos|azure|baidu|beats|bible
        |bingo|black|boats|bosch|build|canon|cards|chase|cheap|cisco|citic|click|cloud
        |coach|codes|crown|cymru|dabur|dance|deals|delta|dodge|drive|dubai|earth|edeka
        |email|epost|epson|faith|fedex|final|forex|forum|gallo|games|gifts|gives|glade
        |glass|globo|gmail|green|gripe|group|gucci|guide|homes|honda|horse|house|hyatt
        |ikano|intel|irish|iveco|jetzt|koeln|kyoto|lamer|lease|legal|lexus|lilly|linde
        |lipsy|lixil|loans|locus|lotte|lotto|lupin|macys|mango|media|miami|money|mopar
        |movie|nadex|nexus|nikon|ninja|nokia|nowtv|omega|osaka|paris|parts|party|phone
        |photo|pizza|place|poker|praxi|press|prime|promo|quest|radio|rehab|reise|ricoh
        |rocks|rodeo|rugby|salon|sener|seven|sharp|shell|shoes|skype|sling|smart|smile
        |solar|space|sport|stada|store|study|style|sucks|swiss|tatar|tires|tirol|tmall
        |today|tokyo|tools|toray|total|tours|trade|trust|tunes|tushu|ubank|vegas|video
        |vodka|volvo|wales|watch|weber|weibo|works|world|xerox|yahoo|zippo|aarp|able
        |adac|aero|aigo|akdn|ally|amex|arab|army|arpa|arte|asda|asia|audi|auto|baby|band
        |bank|bbva|beer|best|bike|bing|blog|blue|bofa|bond|book|buzz|cafe|call|camp|care
        |cars|casa|case|cash|cbre|cern|chat|citi|city|club|cool|coop|cyou|data|date|dclk
        |deal|dell|desi|diet|dish|docs|doha|duck|duns|dvag|erni|fage|fail|fans|farm|fast
        |fiat|fido|film|fire|fish|flir|food|ford|free|fund|game|gbiz|gent|ggee|gift|gmbh
        |gold|golf|goog|guge|guru|hair|haus|hdfc|help|here|hgtv|host|hsbc|icbc|ieee|imdb
        |immo|info|itau|java|jeep|jobs|jprs|kddi|kiwi|kpmg|kred|land|lego|lgbt|lidl|life
        |like|limo|link|live|loan|loft|love|ltda|luxe|maif|meet|meme|menu|mini|mint|mobi
        |moda|moto|name|navy|news|next|nico|nike|ollo|open|page|pars|pccw|pics|ping|pink
        |play|plus|pohl|porn|post|prod|prof|qpon|raid|read|reit|rent|rest|rich|rmit|room
        |rsvp|ruhr|safe|sale|sarl|save|saxo|scor|scot|seat|seek|sexy|shaw|shia|shop|show
        |silk|sina|site|skin|sncf|sohu|song|sony|spot|star|surf|talk|taxi|team|tech|teva
        |tiaa|tips|town|toys|tube|vana|visa|viva|vivo|vote|voto|wang|weir|wien|wiki|wine
        |work|xbox|yoga|zara|zero|zone|aaa|abb|abc|aco|ads|aeg|afl|aig|anz|aol|app|art
        |aws|axa|bar|bbc|bbt|bcg|bcn|bet|bid|bio|biz|bms|bmw|bnl|bom|boo|bot|box|buy|bzh
        |cab|cal|cam|car|cat|cba|cbn|cbs|ceb|ceo|cfa|cfd|com|crs|csc|dad|day|dds|dev|dhl
        |diy|dnp|dog|dot|dtv|dvr|eat|eco|edu|esq|eus|fan|fit|fly|foo|fox|frl|ftr|fun|fyi
        |gal|gap|gdn|gea|gle|gmo|gmx|goo|gop|got|gov|hbo|hiv|hkt|hot|how|ibm|ice|icu|ifm
        |inc|ing|ink|int|ist|itv|jcb|jcp|jio|jlc|jll|jmp|jnj|jot|joy|kfh|kia|kim|kpn|krd
        |lat|law|lds|llc|lol|lpl|ltd|man|map|mba|med|men|mil|mit|mlb|mls|mma|moe|moi|mom
        |mov|msd|mtn|mtr|nab|nba|nec|net|new|nfl|ngo|nhk|now|nra|nrw|ntt|nyc|obi|off|one
        |ong|onl|ooo|org|ott|ovh|pay|pet|phd|pid|pin|pnc|pro|pru|pub|pwc|qvc|red|ren|ril
        |rio|rip|run|rwe|sap|sas|sbi|sbs|sca|scb|ses|sew|sex|sfr|ski|sky|soy|srl|srt|stc
        |tab|tax|tci|tdk|tel|thd|tjx|top|trv|tui|tvs|ubs|uno|uol|ups|vet|vig|vin|vip|wed
        |win|wme|wow|wtc|wtf|xin|xxx|xyz|you|yun|zip|ac|ad|ae|af|ag|ai|al|am|ao|aq|ar|as
        |at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc
        |cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg
        |er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt
        |gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh
        |ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk
        |ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu
        |nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd
        |se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm
        |tn|to|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm
        |zw)
"""

# matches most valid domain names, including international characters per IDNA
STR_DOMAIN: Final = (
    r"""
    (?:
        # any leading domain components
        (?:[%(STR_CHAR)s]+\.)+
        # possible TLDs
        %(STR_TLD)s
    )
"""
    % locals()
)

# matches most valid domain names, including international characters per IDNA
BYTES_DOMAIN: Final = (
    rb"""
    (?:
        # any leading domain components
        (?:[%(BYTES_CHAR)s]+\.)+
        # possible TLDs
        %(BYTES_TLD)s
    )
"""
    % {k.encode(): v for k, v in locals().items()}
)

# this is the registered set of valid URI schemes
STR_SCHEMES: Final = (
    r"""
    (?:aaa|aaas|about|acap|acct|acd|acr|adiumxtra|adt|afp|afs|aim|amss|android|appdata
        |apt|ar|ari|ark|at|attachment|aw|barion|bb|beshare|bitcoin|bitcoincash|bl|blob
        |bluetooth|bolo|brid|browserext|cabal|calculator|callto|cap|cast|casts|chrome
        |chrome-extension|cid|coap|coap+tcp|coap+ws|coaps|coaps+tcp|coaps+ws
        |com-eventbrite-attendee|content|content-type|crid|cstr|cvs|dab|dat|data|dav
        |dhttp|diaspora|dict|did|dis|dlna-playcontainer|dlna-playsingle|dnp|dns|dntp|doi
        |donau|dpp|drm|drop|dtmi|dtn|dvb|dvx|dweb|ed2k|eid|elsi|embedded|ens|esim
        |ethereum|example|facetime|fax|feed|feedready|fido|file|filesystem|finger
        |first-run-pen-experience|fish|fm|ftp|fuchsia-pkg|geo|gg|git|gitoid|gizmoproject
        |go|gopher|graph|grd|gtalk|h323|ham|hcap|hcp|hs20|http|https|hxxp|hxxps
        |hydrazone|hyper|i0|iax|icap|icon|ilstring|im|imap|info|iotdisco|ipfs|ipn|ipns
        |ipp|ipps|irc|irc6|ircs|iris|iris\.beep|iris\.lwz|iris\.xpc|iris\.xpcs|isostore
        |itms|jabber|jar|jms|keyparc|lastfm|lbry|ldap|ldaps|leaptofrogans|lid|linkid
        |lorawan|lpa|lvlt|machineProvisioningProgressReporter|magnet|mailserver|mailto
        |maps|market|matrix|message|microsoft\.windows\.camera
        |microsoft\.windows\.camera\.multipicker|microsoft\.windows\.camera\.picker|mid
        |mms|modem|mongodb|moz|mqtt|mqtts|ms-access|ms-appinstaller|ms-browser-extension
        |ms-calculator|ms-drive-to|ms-enrollment|ms-excel|ms-eyecontrolspeech
        |ms-gamebarservices|ms-gamingoverlay|ms-getoffice|ms-help|ms-infopath
        |ms-inputapp|ms-launchremotedesktop|ms-lockscreencomponent-config
        |ms-media-stream-id|ms-meetnow|ms-mixedrealitycapture|ms-mobileplans
        |ms-newsandinterests|ms-officeapp|ms-people|ms-personacard|ms-project
        |ms-powerpoint|ms-publisher|ms-recall|ms-remotedesktop|ms-remotedesktop-launch
        |ms-restoretabcompanion|ms-screenclip|ms-screensketch|ms-search|ms-search-repair
        |ms-secondary-screen-controller|ms-secondary-screen-setup|ms-settings
        |ms-settings-airplanemode|ms-settings-bluetooth|ms-settings-camera
        |ms-settings-cellular|ms-settings-cloudstorage|ms-settings-connectabledevices
        |ms-settings-displays-topology|ms-settings-emailandaccounts|ms-settings-language
        |ms-settings-location|ms-settings-lock|ms-settings-nfctransactions
        |ms-settings-notifications|ms-settings-power|ms-settings-privacy
        |ms-settings-proximity|ms-settings-screenrotation|ms-settings-wifi
        |ms-settings-workplace|ms-spd|ms-stickers|ms-sttoverlay|ms-transit-to
        |ms-useractivityset|ms-uup|ms-virtualtouchpad|ms-visio|ms-walk-to|ms-whiteboard
        |ms-whiteboard-cmd|ms-widgetboard|ms-widgets|ms-word|msnim|msrp|msrps|mss|mt
        |mtqp|mtrust|mumble|mupdate|mvn|mvrp|mvrps|news|nfs|ni|nih|nntp|notes|num|ocf
        |oid|onenote|onenote-cmd|opaquelocktoken|openid|openpgp4fpr|otpauth|p1|pack|palm
        |paparazzi|payment|payto|pkcs11|platform|pop|pres|prospero|proxy|pwid|psyc|pttp
        |qb|query|quic-transport|redis|rediss|reload|res|resource|rmi|rsync|rtmfp|rtmp
        |rtsp|rtsps|rtspu|sarif|secondlife|secret-token|service|session|sftp|sgn|shc
        |shelter|shttp|sieve|simpleledger|simplex|sip|sips|skype|smb|smp|sms|smtp|snews
        |snmp|soap\.beep|soap\.beeps|soldat|spiffe|spotify|ssb|ssh|starknet|steam|stun
        |stuns|submit|svn|swh|swid|swidpath|tag|taler|teamspeak|teapot|teapots|tel
        |teliaeid|telnet|tftp|things|thismessage|thzp|tip|tn3270|tool|turn|turns|tv|udp
        |unreal|upt|urn|ut2004|uuid-in-package|v-event|vemmi|ventrilo|ves|videotex|vnc
        |view-source|vscode|vscode-insiders|vsls|w3|wais|wasm|wasm-js|web3|wcr|webcal
        |web+ap|wifi|wpid|ws|wss|wtai|wyciwyg|xcompute|xcon|xcon-userid|xfire
        |xmlrpc\.beep|xmlrpc\.beeps|xmpp|xftp|xrcp|xri|ymsgr|z39\.50|z39\.50r|z39\.50s)
    """
)
BYTES_SCHEMES: Final = STR_SCHEMES.encode()

# matches any valid IPv4 address
IPV4SEG: Final = r"""
    (?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])
"""
STR_IPV4ADDR: Final = (
    r"""
    %(S4)s\.%(S4)s\.%(S4)s\.%(S4)s
    """
    % {"S4": IPV4SEG}
)
BYTES_IPV4ADDR: Final = STR_IPV4ADDR.encode()

# matches any valid IPv6 address, including nested IPv4 addresses and network segments
IPV6SEG: Final = r"""
    (?:[0-9a-f]{1,4})
"""
STR_IPV6ADDR: Final = (
    r"""
    (?:
    fe80:(?:: %(S6)s ){0,4}%%[0-9a-z]+|         # fe80::7:8%%eth0
                                                # fe80::7:8%%1
                                                # (link-local IPv6 with zone index)
    ::(?:ffff(?::0{1,4}){0,1}:){0,1} %(I4)s |   # ::255.255.255.255
                                                # ::ffff:255.255.255.255
                                                # ::ffff:0:255.255.255.255
                                                # (IPv4-mapped IPv6, IPv4-translated)
    (?: %(S6)s :){1,4}: %(I4)s |                # 2001:db8:3:4::192.0.2.33
                                                # 64:ff9b::192.0.2.33
                                                # (IPv4-Embedded IPv6 Address)
    (?: %(S6)s :){7,7} %(S6)s |                 # 1:2:3:4:5:6:7:8
    %(S6)s :(?:(?:: %(S6)s ){1,6})|             # 1::3:4:5:6:7:8 1::3:4:5:6:7:8 1::8
    (?: %(S6)s :){1,2}(?:: %(S6)s ){1,5}|       # 1::4:5:6:7:8 1:2::4:5:6:7:8 1:2::8
    (?: %(S6)s :){1,3}(?:: %(S6)s ){1,4}|       # 1::5:6:7:8 1:2:3::5:6:7:8 1:2:3::8
    (?: %(S6)s :){1,4}(?:: %(S6)s ){1,3}|       # 1::6:7:8 1:2:3:4::6:7:8 1:2:3:4::8
    (?: %(S6)s :){1,5}(?:: %(S6)s ){1,2}|       # 1::7:8 1:2:3:4:5::7:8 1:2:3:4:5::8
    (?: %(S6)s :){1,6}: %(S6)s |                # 1::8 1:2:3:4:5:6::8 1:2:3:4:5:6::8
    (?: %(S6)s :){1,7}:|                        # 1:: 1:2:3:4:5:6:7::
    :(?:(?:: %(S6)s ){1,7}|:)                   # ::2:3:4:5:6:7:8 ::2:3:4:5:6:7:8 ::8 ::
    )
"""
    % {"S6": IPV6SEG, "I4": STR_IPV4ADDR}
)
BYTES_IPV6ADDR: Final = STR_IPV6ADDR.encode()

# matches a proper port, limiting to a 16-bit value
STR_PORT: Final = r"""
    (?: 6553[0-5]       # 65530-65535
      | 655[0-2]\d      # 65500-65529
      | 65[0-4]\d{2}    # 65000-65499
      | 6[0-4]\d{3}     # 60000-64999
      | [1-5]\d{4}      # 10000-59999
      | [1-9]\d{0,3}    # 1-9999
      | 0 )             # 0
"""
BYTES_PORT: Final = STR_PORT.encode()

# matches a netloc with an optional port attached
STR_NETLOC: Final = (
    r"""
    (?: \b(%(STR_DOMAIN)s)(?:(?::%(STR_PORT)s)(?![0-9])|\b)
    |   (?<![0-9.])(%(STR_IPV4ADDR)s)(?:(?::%(STR_PORT)s)(?![0-9])|(?![0-9.]))
    |   \[(%(STR_IPV6ADDR)s)\](?:(?::%(STR_PORT)s)(?![0-9])|(?![0-9.])) )
"""
    % locals()
)
BYTES_NETLOC: Final = (
    rb"""
    (?: \b(%(BYTES_DOMAIN)s)(?:(?::%(BYTES_PORT)s)(?![0-9])|\b)
    |   (?<![0-9.])(%(BYTES_IPV4ADDR)s)(?:(?::%(BYTES_PORT)s)(?![0-9])|(?![0-9.]))
    |   \[(%(BYTES_IPV6ADDR)s)\](?:(?::%(BYTES_PORT)s)(?![0-9])|(?![0-9.])) )
"""
    % {k.encode(): v for k, v in locals().items()}
)

STR_URI_CHAR: Final = r"[-0-9a-z._~]|%[0-9a-f]{2}"
BYTES_URI_CHAR: Final = STR_URI_CHAR.encode()

# matches an entire URL; note that you may end up with included trailing punctuation,
# depending on surrounding context, since technically, we cannot determine whether or
# not the final semicolon in "https://www.google.com/;" is part of the URL or not
STR_URL: Final = (
    # (?:([a-z\d.-]+)://)?    # scheme
    # %(STR_NETLOC)s          # netloc[:port]
    # (?:/[^;?\#<>\s]*)?      # path
    # (?:;[^?\#<>\s]*)?       # parameters
    # (?:\?[^\#<>\s]*)?       # query string
    # (?:\#[^<>\s\(\)]*)?     # fragment
    r"""
    (?P<scheme>%(STR_SCHEMES)s):
    (?P<authority>
        //(?:(?P<userinfo>
            (?P<username>(?:%(STR_URI_CHAR)s|[,/?\#\[\]!$&'()*+,;=])+)
            (?::(?P<password>(?:%(STR_URI_CHAR)s|[:,/?\#\[\]!$&'()*+,;=])+))?
        )@)?
        (?P<host>%(STR_DOMAIN)s|%(STR_IPV4ADDR)s|\[%(STR_IPV6ADDR)s\])
        (?::(?P<port>%(STR_PORT)s))?
    )
    (?P<path>(?(authority)/)(?:%(STR_URI_CHAR)s|[:,/\[\]!$&'()*+,;=@])*)?
    (?:\?(?P<query>(?:%(STR_URI_CHAR)s|[,/?\[\]!$&'()*+,;=])+))?
    (?:\#(?P<fragment>(?:%(STR_URI_CHAR)s|[,/?\#\[\]!$&'()*+,;=])+))?
    """
    % locals()
)
BYTES_URL: Final = (
    # (?:([a-z\d.-]+)://)?    # scheme
    # %(BYTES_NETLOC)s        # netloc[:port]
    # (?:/[^;?\#<>\s]*)?      # path
    # (?:;[^?\#<>\s]*)?       # parameters
    # (?:\?[^\#<>\s]*)?       # query string
    # (?:\#[^<>\s\(\)]*)?     # fragment
    rb"""
    (?P<scheme>%(BYTES_SCHEMES)s):
    (?P<authority>
        //(?:(?P<userinfo>
            (?P<username>(?:%(BYTES_URI_CHAR)s|[,/?\#\[\]!$&'()*+,;=])+)
            (?::(?P<password>(?:%(BYTES_URI_CHAR)s|[:,/?\#\[\]!$&'()*+,;=])+))?
        )@)?
        (?P<host>%(BYTES_DOMAIN)s|%(BYTES_IPV4ADDR)s|\[%(BYTES_IPV6ADDR)s\])
        (?::(?P<port>%(BYTES_PORT)s))?
    )
    (?P<path>(?(authority)/)(?:%(BYTES_URI_CHAR)s|[:,/\[\]!$&'()*+,;=@])*)?
    (?:\?(?P<query>(?:%(BYTES_URI_CHAR)s|[,/?\[\]!$&'()*+,;=])+))?
    (?:\#(?P<fragment>(?:%(BYTES_URI_CHAR)s|[,/?\#\[\]!$&'()*+,;=])+))?
    """
    % {k.encode(): v for k, v in locals().items()}
)

# matches URIs; note the difference between URL and URI
STR_URI: Final = (
    r"""
    (?P<scheme>%(STR_SCHEMES)s):
    (?P<authority>
        //(?:(?P<userinfo>
            (?P<username>(?:%(STR_URI_CHAR)s|[,/?\#\[\]!$&'()*+,;=])+)
            (?::(?P<password>(?:%(STR_URI_CHAR)s|[:,/?\#\[\]!$&'()*+,;=])+))?
        )@)?
        (?P<host>%(STR_DOMAIN)s|%(STR_IPV4ADDR)s|\[%(STR_IPV6ADDR)s\])
        (?::(?P<port>%(STR_PORT)s))?
    )?
    (?P<path>(?(authority)/)(?:%(STR_URI_CHAR)s|[:,/\[\]!$&'()*+,;=@])*)?
    (?:\?(?P<query>(?:%(STR_URI_CHAR)s|[,/?\[\]!$&'()*+,;=])+))?
    (?:\#(?P<fragment>(?:%(STR_URI_CHAR)s|[,/?\#\[\]!$&'()*+,;=])+))?
    """
    % locals()
)
BYTES_URI: Final = (
    rb"""
    (?P<scheme>%(BYTES_SCHEMES)s):
    (?P<authority>
        //(?:(?P<userinfo>
            (?P<username>(?:%(BYTES_URI_CHAR)s|[,/?\#\[\]!$&'()*+,;=])+)
            (?::(?P<password>(?:%(BYTES_URI_CHAR)s|[:,/?\#\[\]!$&'()*+,;=])+))?
        )@)?
        (?P<host>%(BYTES_DOMAIN)s|%(BYTES_IPV4ADDR)s|\[%(BYTES_IPV6ADDR)s\])
        (?::(?P<port>%(BYTES_PORT)s))?
    )?
    (?P<path>(?(authority)/)(?:%(BYTES_URI_CHAR)s|[:,/\[\]!$&'()*+,;=@])*)?
    (?:\?(?P<query>(?:%(BYTES_URI_CHAR)s|[,/?\[\]!$&'()*+,;=])+))?
    (?:\#(?P<fragment>(?:%(BYTES_URI_CHAR)s|[,/?\#\[\]!$&'()*+,;=])+))?
    """
    % {k.encode(): v for k, v in locals().items()}
)

STR_DATA_URI: Final = r"""
    data:
    (?P<mimetype>.*?(?:;[^;]*)*?)
    (?:;(?P<base64>base64))?
    ,(?P<data>[^;,]*)
"""
BYTES_DATA_URI: Final = STR_DATA_URI.encode()


########################################################################################


_T = TypeVar("_T", str, bytes)
Match = re.Match[_T]
AnyMatch = Match[str] | Match[bytes]
END: Final = sys.maxsize


class _BaseMatcher:
    STR_FULL: ClassVar[re.Pattern[str]]
    STR_PARTIAL: ClassVar[re.Pattern[str]]
    BYTES_FULL: ClassVar[re.Pattern[bytes]]
    BYTES_PARTIAL: ClassVar[re.Pattern[bytes]]

    @classmethod
    def match(cls, what: _T, pos=0, endpos=END) -> Match[_T] | None:
        if isinstance(what, str):
            return cls.STR_FULL.match(what, pos, endpos)
        else:
            return cls.BYTES_FULL.match(what, pos, endpos)

    @classmethod
    def search(cls, what: _T, pos=0, endpos=END) -> Match[_T] | None:
        if isinstance(what, str):
            return cls.STR_PARTIAL.search(what, pos, endpos)
        else:
            return cls.BYTES_PARTIAL.search(what, pos, endpos)

    @classmethod
    def findall(cls, what: _T, pos=0, endpos=END) -> list[_T]:
        matches = []
        for match in cls.finditer(what, pos, endpos):
            matches.append(match.group(0))
        return matches

    @classmethod
    def finditer(cls, what: _T, pos=0, endpos=END) -> Iterator[Match[_T]]:
        if isinstance(what, str):
            return cls.STR_PARTIAL.finditer(what, pos, endpos)
        else:
            return cls.BYTES_PARTIAL.finditer(what, pos, endpos)


class _NetlocWithPortMatcher(_BaseMatcher):
    STR_WITH_PORT: ClassVar[re.Pattern[str]]
    BYTES_WITH_PORT: ClassVar[re.Pattern[bytes]]

    @classmethod
    def split(cls, what: _T) -> tuple[str, int | None]:
        if isinstance(what, str):
            if not (m := cls.STR_WITH_PORT.match(what)):
                raise ValueError(what)
        else:
            if not (m := cls.BYTES_WITH_PORT.match(what)):
                raise ValueError(what)
        domain, port, *_ = *filter(None, m.groups()), None
        if isinstance(domain, bytes):
            domain = domain.decode()
        return domain, (port and int(port) or None)


def expand_idna_domain(domain: _T) -> Iterator[str]:
    if isinstance(domain, str):
        yield domain
        yield domain.encode("idna").decode()
        try:
            yield domain.encode().decode("idna")
        except UnicodeDecodeError:
            pass
    else:
        yield domain.decode()


########################################################################################


class netloc(_BaseMatcher):
    STR_FULL: ClassVar = re.compile(
        r"^%(NETLOC)s$" % {"NETLOC": STR_NETLOC}, re.I | re.X
    )
    STR_PARTIAL: ClassVar = re.compile(
        r"%(NETLOC)s" % {"NETLOC": STR_NETLOC}, re.I | re.X
    )
    BYTES_FULL: ClassVar = re.compile(
        rb"^%(NETLOC)s$" % {b"NETLOC": BYTES_NETLOC}, re.I | re.X
    )
    BYTES_PARTIAL: ClassVar = re.compile(
        rb"%(NETLOC)s" % {b"NETLOC": BYTES_NETLOC}, re.I | re.X
    )


class url(_BaseMatcher):
    STR_FULL: ClassVar = re.compile(r"^%(URL)s$" % {"URL": STR_URL}, re.I | re.X)
    STR_PARTIAL: ClassVar = re.compile(r"\b%(URL)s" % {"URL": STR_URL}, re.I | re.X)
    BYTES_FULL: ClassVar = re.compile(rb"^%(URL)s$" % {b"URL": BYTES_URL}, re.I | re.X)
    BYTES_PARTIAL: ClassVar = re.compile(
        rb"\b%(URL)s" % {b"URL": BYTES_URL}, re.I | re.X
    )


class uri(_BaseMatcher):
    STR_FULL: ClassVar = re.compile(r"^%(URI)s$" % {"URI": STR_URI}, re.I | re.X)
    STR_PARTIAL: ClassVar = re.compile(r"\b%(URI)s" % {"URI": STR_URI}, re.I | re.X)
    BYTES_FULL: ClassVar = re.compile(rb"^%(URI)s$" % {b"URI": BYTES_URI}, re.I | re.X)
    BYTES_PARTIAL: ClassVar = re.compile(
        rb"\b%(URI)s" % {b"URI": BYTES_URI}, re.I | re.X
    )


class data_uri(_BaseMatcher):
    STR_FULL: ClassVar = re.compile(r"^%(URI)s$" % {"URI": STR_DATA_URI}, re.I | re.X)
    STR_PARTIAL: ClassVar = re.compile(
        r"\b%(URI)s" % {"URI": STR_DATA_URI}, re.I | re.X
    )
    BYTES_FULL: ClassVar = re.compile(
        rb"^%(URI)s$" % {b"URI": BYTES_DATA_URI}, re.I | re.X
    )
    BYTES_PARTIAL: ClassVar = re.compile(
        rb"\b%(URI)s" % {b"URI": BYTES_DATA_URI}, re.I | re.X
    )

    @classmethod
    def evaluate(cls, value: _T) -> tuple[str, bytes]:
        raw = value.decode() if isinstance(value, bytes) else value
        if (m := cls.match(raw)) is None:
            raise ValueError(value)
        parts = m.groupdict()

        # this default mimetype is per the standard
        mimetype = parts.get("mimetype") or "text/plain; charset=US-ASCII"
        data = b""

        if d := parts.get("data"):
            if parts.get("base64"):
                data = base64.b64decode(d)
            else:
                data = urllib.parse.unquote_to_bytes(d)

        return mimetype, data


class domain(_NetlocWithPortMatcher):
    STR_FULL: ClassVar = re.compile(
        r"^%(DOMAIN)s$" % {"DOMAIN": STR_DOMAIN}, re.I | re.X
    )
    STR_PARTIAL: ClassVar = re.compile(
        r"\b%(DOMAIN)s\b" % {"DOMAIN": STR_DOMAIN}, re.I | re.X
    )
    STR_WITH_PORT: ClassVar = re.compile(
        r"^(%(DOMAIN)s)(?::(%(PORT)s))?$" % {"DOMAIN": STR_DOMAIN, "PORT": STR_PORT},
        re.X | re.I,
    )
    BYTES_FULL: ClassVar = re.compile(
        rb"^%(DOMAIN)s$" % {b"DOMAIN": BYTES_DOMAIN}, re.I | re.X
    )
    BYTES_PARTIAL: ClassVar = re.compile(
        rb"\b%(DOMAIN)s\b" % {b"DOMAIN": BYTES_DOMAIN}, re.I | re.X
    )
    BYTES_WITH_PORT: ClassVar = re.compile(
        rb"^(%(DOMAIN)s)(?::(%(PORT)s))?$"
        % {b"DOMAIN": BYTES_DOMAIN, b"PORT": BYTES_PORT},
        re.X | re.I,
    )


class ipv4(_NetlocWithPortMatcher):
    STR_FULL: ClassVar = re.compile(r"^%(IPV4)s$" % {"IPV4": STR_IPV4ADDR}, re.I | re.X)
    STR_PARTIAL: ClassVar = re.compile(
        r"(?<![0-9.])%(IPV4)s(?![0-9.])" % {"IPV4": STR_IPV4ADDR}, re.I | re.X
    )
    STR_WITH_PORT: ClassVar = re.compile(
        r"^(%(IPV4)s)(?::(%(PORT)s))?$" % {"IPV4": STR_IPV4ADDR, "PORT": STR_PORT},
        re.X | re.I,
    )
    BYTES_FULL: ClassVar = re.compile(
        rb"^%(IPV4)s$" % {b"IPV4": BYTES_IPV4ADDR}, re.I | re.X
    )
    BYTES_PARTIAL: ClassVar = re.compile(
        rb"(?<![0-9.])%(IPV4)s(?![0-9.])" % {b"IPV4": BYTES_IPV4ADDR}, re.I | re.X
    )
    BYTES_WITH_PORT: ClassVar = re.compile(
        rb"^(%(IPV4)s)(?::(%(PORT)s))?$"
        % {b"IPV4": BYTES_IPV4ADDR, b"PORT": BYTES_PORT},
        re.X | re.I,
    )


class ipv6(_NetlocWithPortMatcher):
    STR_FULL: ClassVar = re.compile(r"^%(IPV6)s$" % {"IPV6": STR_IPV6ADDR}, re.I | re.X)
    STR_PARTIAL: ClassVar = re.compile(
        r"(?<![0-9a-f:])%(IPV6)s(?![0-9a-f:])" % {"IPV6": STR_IPV6ADDR}, re.I | re.X
    )
    STR_WITH_PORT: ClassVar = re.compile(
        r"^(?:(%(IPV6)s)|\[(%(IPV6)s)\]:(%(PORT)s))$"
        % {"IPV6": STR_IPV6ADDR, "PORT": STR_PORT},
        re.X | re.I,
    )
    BYTES_FULL: ClassVar = re.compile(
        rb"^%(IPV6)s$" % {b"IPV6": BYTES_IPV6ADDR}, re.I | re.X
    )
    BYTES_PARTIAL: ClassVar = re.compile(
        rb"(?<![0-9a-f:])%(IPV6)s(?![0-9a-f:])" % {b"IPV6": BYTES_IPV6ADDR}, re.I | re.X
    )
    BYTES_WITH_PORT: ClassVar = re.compile(
        rb"^(?:(%(IPV6)s)|\[(%(IPV6)s)\]:(%(PORT)s))$"
        % {b"IPV6": BYTES_IPV6ADDR, b"PORT": BYTES_PORT},
        re.X | re.I,
    )
