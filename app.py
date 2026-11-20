import os
import re
import hmac
import secrets
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for,
    render_template_string, abort, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyber_kurd.db")

CATEGORIES = [
    "Linux", "Termux", "Python", "C++", "Cybersecurity",
    "OSINT", "Ethical Hacking", "Networking", "Technology"
]

LESSONS = [{'id': 'linux', 'name': 'Linux', 'icon': '🐧', 'intro': 'بنەماکانی Linux، فایل و فۆڵدەر، پرۆسە و فەرمانە بنەڕەتییەکان.', 'lessons': [('linux-1', 'دەستپێکردن بە Linux', 'Linux چییە؟', 'Linux سیستەمێکی کارپێکردنی ئازاد و کراوەیە. زۆر لە سێرڤەرەکان، کۆمپیوتەرەکان و ئامێرە زیرەکەکان بەکاری دەهێنن.', 'pwd\nwhoami\nuname -a\ncat /etc/os-release', 'ئەم فەرمانانە زانیاریی شوێنی ئێستا، بەکارهێنەر و جۆری سیستەم پیشان دەدەن.'), ('linux-2', 'فایل و فۆڵدەر', 'ڕێکخستنی فایلەکان', 'فەرمانەکانی ls و cd و mkdir بۆ بینین و گۆڕینی شوێن و دروستکردنی فۆڵدەر بەکاردێن.', 'ls -la\npwd\nmkdir practice\ncd practice\n touch note.txt', 'تەنها لە فۆڵدەری ڕاهێنانەکەت کار بکە و پێش سڕینەوەی فایل دڵنیابە.'), ('linux-3', 'دەستکاری فایل', 'خوێندنەوە و نووسین', 'cat بۆ خوێندنەوەی فایل و nano بۆ دەستکاریکردنی دەقی سادە بەکاردێن.', "echo 'Hello Linux' > hello.txt\ncat hello.txt\nnano hello.txt", 'ئەم نموونانە فایلێکی نوێ دروست دەکەن و ناوەڕۆکەکەی پیشان دەدەن.'), ('linux-4', 'Terminal و Shell', 'ناسینی ترمیناڵ', 'Terminal شوێنی نووسینی فەرمانە و Shell فەرمانەکان وەردەگرێت و جێبەجێیان دەکات.', 'echo $SHELL\nwhoami\npwd', 'فەرمانەکان لە فۆڵدەری ڕاهێناندا تاقی بکەرەوە.'), ('linux-5', 'دروستکردنی فایل', 'touch و echo', 'touch فایلێکی بەتاڵ دروست دەکات و echo دەتوانێت دەق بنووسێت.', "touch note.txt\necho 'Hello Linux' > note.txt\ncat note.txt", 'نیشانەی > ناوەڕۆکی پێشوو دەگۆڕێت؛ >> زیادکردنە.'), ('linux-6', 'کۆپی و گواستنەوە', 'cp و mv', 'cp فایل کۆپی دەکات؛ mv دەیگوازێتەوە یان ناوی دەگۆڕێت.', 'cp note.txt note-copy.txt\nmv note-copy.txt backup.txt', 'پێش overwrite پاشەکەوتی فایلە گرنگەکان بگرە.'), ('linux-7', 'گەڕان لە فایل', 'grep و find', 'grep بۆ گەڕان لە ناو دەق و find بۆ دۆزینەوەی فایلەکانە.', "grep -n 'Linux' note.txt\nfind . -name '*.txt'", 'گەڕانەکە لە فۆڵدەری پرۆژەی خۆتدا بکە.'), ('linux-8', 'دەستکاریکردنی دەق', 'nano', 'nano دەستکاریکەری دەقی سادەیە بۆ نووسینی فایل و کۆد.', 'nano note.txt', 'Ctrl+O بۆ پاشەکەوت و Ctrl+X بۆ دەرچوون.'), ('linux-9', 'مۆڵەتی فایل', 'Permission', 'مۆڵەت دیاری دەکات کێ دەتوانێت فایل بخوێنێتەوە یان دەستکاری بکات.', 'ls -l\nstat note.txt', 'مۆڵەتی فایلەکانی سیستەم مەگۆڕە.'), ('linux-10', 'بەکارهێنەر و گرووپ', 'id و groups', 'Linux بەکارهێنەر و گرووپ بەکار دەهێنێت بۆ کۆنترۆڵی دەستگەیشتن.', 'whoami\nid\ngroups', 'تەنها زانیاریی هەژماری خۆت بخوێنەوە.'), ('linux-11', 'دامەزراندنی پەکەج', 'apt', 'apt لە Debian و Ubuntu بۆ نوێکردنەوە و دامەزراندنی پەکەجەکانە.', 'sudo apt update\napt search nano', 'پەکەج لە سەرچاوەی فەرمی دامەزرێنە.'), ('linux-12', 'پرۆسەکان', 'ps و top', 'پرۆسە بەرنامەیەکی کارایە؛ ps و top بۆ بینینی دۆخی پرۆسەکانن.', 'ps aux\ntop', 'پرۆسەی نەناسراو مەکوژە.'), ('linux-13', 'شوێنی دیسک', 'df و du', 'df شوێنی بەردەست پیشان دەدات؛ du قەبارەی فۆڵدەر هەژمار دەکات.', 'df -h\ndu -sh .', 'فۆڵدەری پرۆژەکەت بپشکنە.'), ('linux-14', 'ئەرشیڤ', 'tar', 'tar فایلەکان لە ئەرشیڤێکدا کۆدەکاتەوە.', 'tar -czf practice.tar.gz practice\nls -lh practice.tar.gz', 'تەنها فایلەکانی خۆت ئەرشیڤ بکە.'), ('linux-15', 'لۆگ', 'journalctl', 'لۆگ تۆماری ڕووداوەکانی سیستەمە و بۆ تێگەیشتن لە هەڵەکان یارمەتیدەرە.', 'journalctl -n 20', 'لۆگی سیستەم مەسڕەوە.')]}, {'id': 'termux', 'name': 'Termux', 'icon': '📱', 'intro': 'فێربوونی Termux لە Android و بەڕێوەبردنی پەکەج و پرۆژەکان.', 'lessons': [('termux-1', 'ئامادەکردنی Termux', 'نوێکردنەوەی پەکەجەکان', 'Termux ژینگەیەکی terminal ـە لە Android. پێش دامەزراندنی پەکەجەکان، پەکەجە بنەڕەتییەکان نوێ بکەرەوە.', 'pkg update && pkg upgrade', 'هەر فەرمانێک تێنەگەیشتی، پێش جێبەجێکردنی بپرسە.'), ('termux-2', 'دامەزراندنی ئامراز', 'دامەزراندنی Python و Git', 'pkg بۆ دامەزراندنی پەکەجەکان بەکاردێت. Python بۆ پرۆگرامسازی و Git بۆ بەڕێوەبردنی وەشانەکانی کۆد بەکاردێن.', 'pkg install python git nano -y\npython --version\ngit --version', 'سەرچاوەی پەکەجەکان تەنها لە شوێنی متمانەپێکراو و فەرمی وەربگرە.'), ('termux-3', 'فۆڵدەر و فایل', 'دروستکردنی پرۆژە', 'هەر پرۆژەیەک لە فۆڵدەرێکی جیاواز ڕێک بخە بۆ ئەوەی فایلەکانت تێکەڵ نەبن.', 'mkdir my-project\ncd my-project\npwd\nls -la', 'ئەم نموونەیە تەنها فۆڵدەرێکی ڕاهێنان دروست دەکات.'), ('termux-4', 'نوێکردنەوەی پەکەج', 'pkg update و upgrade', 'pkg update لیستی پەکەج نوێ دەکاتەوە و upgrade پەکەجە دامەزراوەکان نوێ دەکاتەوە.', 'pkg update\npkg upgrade', 'پێش نوێکردنەوە پەیوەندی ئینتەرنێتت هەبێت.'), ('termux-5', 'گەڕان بۆ پەکەج', 'pkg search', 'بە pkg search دەتوانیت پەکەجی پێویست بدۆزیتەوە.', 'pkg search python\npkg show python', 'ناوی پەکەج و سەرچاوەکەی بپشکنە.'), ('termux-6', 'دامەزراندنی ئامراز', 'pkg install', 'pkg install پەکەجی دیاریکراو دادەمەزرێنێت.', 'pkg install python git nano', 'تەنها ئامرازی پێویست دامەزرێنە.'), ('termux-7', 'شوێنی ئێستا', 'pwd و cd', 'pwd شوێنی ئێستا پیشان دەدات و cd فۆڵدەر دەگۆڕێت.', 'pwd\ncd ~\nls -la', 'فۆڵدەری home بۆ پرۆژەکان بەکاربهێنە.'), ('termux-8', 'دروستکردنی فۆڵدەر', 'mkdir', 'mkdir فۆڵدەر دروست دەکات.', 'mkdir -p projects/demo\ncd projects/demo', 'ناوی ڕوون بۆ فۆڵدەرەکان هەڵبژێرە.'), ('termux-9', 'فایل دروستکردن', 'touch و echo', 'touch فایل دروست دەکات و echo دەق دەنووسێت.', "touch hello.txt\necho 'Salaw' > hello.txt\ncat hello.txt", 'فایلەکە لە فۆڵدەری پرۆژەدا هەڵبگرە.'), ('termux-10', 'دەستکاری فایل', 'nano', 'nano دەستکاریکەری دەقە بۆ نووسینی کۆد.', 'nano hello.py', 'Ctrl+O پاشەکەوت و Ctrl+X دەرچوون.'), ('termux-11', 'Python', 'جێبەجێکردنی Python', 'Python سکریپتەکانی .py جێبەجێ دەکات.', 'pkg install python\npython --version\npython hello.py', 'کۆدی خۆت بخوێنەوە پێش جێبەجێکردن.'), ('termux-12', 'Git', 'بەڕێوەبردنی کۆد', 'Git مێژووی گۆڕانکارییەکانی پرۆژە ڕێک دەخات.', 'pkg install git\ngit --version\ngit status', 'تەنها repo ـی خۆت بەڕێوەببە.'), ('termux-13', 'دەستگەیشتن بە فایلەکان', 'termux-setup-storage', 'ئەم فەرمانە داوای مۆڵەتی دەستگەیشتن بە فایلەکانی Android دەکات.', 'termux-setup-storage\nls ~/storage/downloads', 'مۆڵەتەکان بە ئاگاداری بدە.'), ('termux-14', 'سێرڤەری ناوخۆیی', 'http.server', 'Python دەتوانێت فایلەکانی فۆڵدەرێک لەسەر ئامێری خۆت پیشان بدات.', 'python -m http.server 8080', 'تەنها لە فۆڵدەری گشتیی پرۆژە و تۆڕی متمانەپێکراو بەکاری بهێنە.'), ('termux-15', 'وەستاندنی بەرنامە', 'Ctrl+C و exit', 'Ctrl+C زۆرجار بەرنامەی ترمیناڵی کارا ڕادەگرێت؛ exit لە shell دەردەچێت.', '# Ctrl+C\nexit', 'پێش وەستاندن دڵنیابە هیچ کارێکی گرنگ نەماوە.')]}, {'id': 'python', 'name': 'Python', 'icon': '🐍', 'intro': 'فێربوونی Python لە سفرەوە، لەگەڵ نموونە و ڕاهێنان.', 'lessons': [('python-1', 'یەکەم کۆد', 'Hello World', 'Python زمانێکی پرۆگرامسازییە. print بۆ پیشاندانی دەق و دەرئەنجام بەکاردێت.', "print('Hello, Cyber Kurd!')", 'فایلێک بە ناوی main.py دروست بکە و بە python main.py جێبەجێی بکە.'), ('python-2', 'گۆڕاوەکان', 'Variables', 'گۆڕاو شوێنێکە بۆ هەڵگرتنی نرخ. دەتوانیت ژمارە و دەق تێیدا هەڵبگریت.', "name = 'Kurd'\nage = 16\nprint(name)\nprint(age)", 'نرخەکان بگۆڕە و دەرئەنجامەکە ببینە.'), ('python-3', 'مەرجەکان', 'if و else', 'if بۆ بڕیاردان بە پێی مەرج بەکاردێت. ئەگەر مەرجەکە ڕاست بێت، بلۆکی یەکەم جێبەجێ دەبێت.', "score = 75\nif score >= 50:\n    print('Pass')\nelse:\n    print('Try again')", 'نرخی score بگۆڕە بۆ 35 و دەرئەنجامەکە تاقی بکەرەوە.'), ('python-4', 'جۆری داتا', 'str int float bool', 'Python جۆری داتا وەک دەق، ژمارەی تەواو، ژمارەی خاڵدار و boolean هەیە.', "print(type('text'))\nprint(type(12))\nprint(type(3.5))\nprint(type(True))", 'جۆری چەند نرخێک بپشکنە.'), ('python-5', 'وەرگرتنی زانیاری', 'input', 'input زانیاری لە بەکارهێنەر وەردەگرێت.', "name = input('ناوت چییە؟ ')\nprint('سڵاو', name)", 'پرۆگرامێکی پرسیارکردنی ناو دروست بکە.'), ('python-6', 'کردارە ژمێریارییەکان', 'Operators', '+, -, *, / و % بۆ ژمێریاری بەکاردێن.', 'a=12\nb=5\nprint(a+b, a-b, a*b, a/b, a%b)', 'نرخەکان بگۆڕە.'), ('python-7', 'لووپی for', 'دووبارەکردنەوە', 'for بۆ دووبارەکردنەوەی کردار لەسەر مەودا یان لیست بەکاردێت.', 'for n in range(1, 6):\n    print(n)', 'مەوداکە تا 10 درێژ بکە.'), ('python-8', 'لووپی while', 'دووبارەکردنەوە بە مەرج', 'while تا ڕاستبوونی مەرجەکە دووبارە دەبێتەوە.', 'n=1\nwhile n<=3:\n    print(n)\n    n += 1', 'گۆڕینی n لەبیر مەکە بۆ ڕێگریکردن لە لووپی بێکۆتایی.'), ('python-9', 'لیست', 'Lists', 'list چەند نرخێک لە ڕیزێکدا هەڵدەگرێت.', "colors=['red','green']\ncolors.append('blue')\nprint(colors)", 'توخمێک زیاد بکە.'), ('python-10', 'فەنکشن', 'def و return', 'فەنکشن کۆدی دووبارە بەکارهاتوو ڕێک دەخات.', 'def add(a,b):\n    return a+b\nprint(add(2,3))', 'فەنکشنی کەمکردنەوە بنووسە.'), ('python-11', 'فایل', 'File handling', 'with open فایل دەکاتەوە و بە شێوەیەکی ڕێک دادەخات.', "with open('note.txt','w') as f:\n    f.write('Hello')\nwith open('note.txt') as f:\n    print(f.read())", 'تەنها فایلێکی ڕاهێنان بەکاربهێنە.'), ('python-12', 'هەڵەکان', 'try و except', 'try/except ڕێگەت پێدەدات هەڵەی چاوەڕوانکراو بەڕێوەببەیت.', "try:\n    n=int(input('ژمارە: '))\nexcept ValueError:\n    print('ژمارە بنووسە')", 'دەق لەبری ژمارە تاقی بکەرەوە.'), ('python-13', 'مۆدیول', 'import', 'مۆدیول کۆدی ئامادەیە کە بە import بەکاری دەهێنیت.', 'import math\nprint(math.sqrt(25))', 'فەنکشنی math ـی تر تاقی بکەرەوە.'), ('python-14', 'کتێبخانە و pip', 'بەڕێوەبردنی پەکەج', 'pip بۆ دامەزراندنی کتێبخانەی Python بەکاردێت.', 'python -m pip --version', 'پێش دامەزراندن پەکەج و سەرچاوەکە بپشکنە.'), ('python-15', 'ژینگەی venv', 'جیاکردنەوەی پرۆژە', 'venv کتێبخانەکانی پرۆژەیەک لە پرۆژەی تر جیا دەکاتەوە.', 'python -m venv .venv', 'ژینگەی ڕاهێنانت لە پرۆژەکەدا دروست بکە.')]}, {'id': 'cpp', 'name': 'C++', 'icon': '⚙️', 'intro': 'بنەماکانی C++، variable، input/output و مەرجەکان.', 'lessons': [('cpp-1', 'یەکەم بەرنامە', 'Hello World بە C++', 'C++ زمانێکی پرۆگرامسازییە. cout بۆ نیشاندانی دەق بەکاردێت.', '#include <iostream>\nusing namespace std;\nint main() {\n    cout << "Hello, Cyber Kurd!" << endl;\n    return 0;\n}', 'لە کۆمپیوتەر compiler ـێکی C++ پێویستە. لە Termux دەتوانیت clang دامەزرێنیت.'), ('cpp-2', 'گۆڕاوەکان', 'Variables لە C++', 'int بۆ ژمارەی تەواو و string بۆ دەق بەکاردێت.', '#include <iostream>\n#include <string>\nusing namespace std;\nint main() {\n    string name = "Kurd";\n    int level = 1;\n    cout << name << " " << level << endl;\n    return 0;\n}', 'جۆری گۆڕاو و نرخەکانی بگۆڕە و تاقی بکەرەوە.'), ('cpp-3', 'مەرجەکان', 'if و else لە C++', '#include <iostream>\nusing namespace std;\nint main() {\n    int score = 75;\n    if (score >= 50) cout << "Pass";\n    else cout << "Try again";\n    return 0;\n}', 'بەهای score بگۆڕە و ببینە کام دەرئەنجام دەردەکەوێت.'), ('cpp-4', 'جۆری گۆڕاو', 'int و double و string', 'C++ جۆری جیاوازی داتا هەیە؛ جۆری دروست یارمەتیدەرە بۆ بەکارهێنانی بیرگە.', 'int age=15;\ndouble price=2.5;\nstd::string city="Erbil";', 'نرخەکان بگۆڕە.'), ('cpp-5', 'cin و cout', 'Input و Output', 'cout بۆ پیشاندانی دەرئەنجام و cin بۆ وەرگرتنی زانیارییە.', 'int n;\nstd::cin >> n;\nstd::cout << n;', 'ژمارەی جیاواز تاقی بکەرەوە.'), ('cpp-6', 'Operators', 'کردارەکان', 'C++ کردارە ژمێریاری و بەراوردکارییەکان پشتیوانی دەکات.', "int a=8,b=3;\nstd::cout << a+b << ' ' << a*b;", '/ و % تاقی بکەرەوە.'), ('cpp-7', 'switch', 'چەند هەڵبژاردە', 'switch بۆ هەڵبژاردنی case بە پێی نرخ بەکاردێت.', 'int day=2;\nswitch(day){case 1: std::cout<<"A"; break; case 2: std::cout<<"B"; break; default: std::cout<<"?";}', 'case ـێکی تر زیاد بکە.'), ('cpp-8', 'for loop', 'لووپی for', 'for بۆ دووبارەکردنەوە بە ژمارەی دیاریکراوە.', "for(int i=1;i<=5;i++) std::cout<<i<<' ';", 'مەوداکە بگۆڕە.'), ('cpp-9', 'while loop', 'لووپی while', 'while تا ڕاستبوونی مەرجەکە دووبارە دەبێتەوە.', 'int i=1;\nwhile(i<=3){std::cout<<i; i++;}', 'گۆڕینی i لەبیر مەکە.'), ('cpp-10', 'فەنکشن', 'Functions', 'فەنکشن کۆد بە ناوێک ڕێک دەخات.', 'int add(int a,int b){return a+b;}', 'فەنکشنی کەمکردنەوە بنووسە.'), ('cpp-11', 'Array', 'ڕیزبەندی داتا', 'array چەند دانەی هەمان جۆر هەڵدەگرێت.', 'int nums[3]={2,4,6};\nstd::cout<<nums[0];', 'index لە سفرەوە دەست پێدەکات.'), ('cpp-12', 'String', 'دەق', 'string بۆ هەڵگرتن و پشکنینی دەقە.', '#include <string>\nstd::string city="Erbil";\nstd::cout<<city.length();', 'دەقێکی نوێ تاقی بکەرەوە.'), ('cpp-13', 'Class و Object', 'OOP', 'class نەخشەیەکە بۆ دروستکردنی object و کۆکردنەوەی داتا و فەنکشن.', 'class Student { public: int level; };', 'class ـێکی خەیاڵی دروست بکە.'), ('cpp-14', 'Reference', 'هەڵگری ناونیشان', 'reference ناوی ترە بۆ هەمان گۆڕاو.', 'int a=5;\nint &r=a;\nr=8;\nstd::cout<<a;', 'گۆڕینی r لەسەر a کاریگەری هەیە.'), ('cpp-15', 'Vector', 'لیستی گۆڕاو', 'vector لە STL لیستێکی گۆڕاوە کە دەتوانێت گەورە و بچووک بێت.', '#include <vector>\nstd::vector<int> v={1,2,3};\nv.push_back(4);', 'توخمێک زیاد بکە.')]}, {'id': 'cybersecurity', 'name': 'Cybersecurity', 'icon': '🛡️', 'intro': 'پاراستنی ئامێر، هەژمار، وشەی نهێنی و تۆڕ.', 'lessons': [('cyber-1', 'پاراستنی هەژمار', 'وشەی نهێنیی بەهێز', 'وشەی نهێنیی جیاواز و درێژ بەکاربهێنە، دوو-هەنگاوی پشتڕاستکردنەوە چالاک بکە و وشەی نهێنی لەگەڵ کەس هاوبەش مەکە.', 'Checklist:\n- Unique password\n- Password manager\n- Two-factor authentication\n- Check account recovery options', 'هیچ کات وشەی نهێنی خۆت لە وێبسایت یان چاتێکدا مەنووسە.'), ('cyber-2', 'پاراستنی مۆبایل', 'بنەماکانی پاراستن', 'سیستەم و ئەپەکان نوێ بکەرەوە، تەنها لە سەرچاوەی متمانەپێکراو دایبەزێنە و مۆڵەتەکانی ئەپەکان بپشکنە.', 'Security checklist:\n1. Update Android\n2. Review app permissions\n3. Use screen lock\n4. Back up important files', 'هەر فایلێکی نەناسراو مەکەرەوە.'), ('cybersecurity-3', 'نهێنیبوون', 'Confidentiality', 'تەنها کەسانی مۆڵەتپێدراو دەبێت بتوانن داتا ببینن.', 'Use unique passwords\nEnable 2FA', 'زانیاری تایبەتی لە شوێنی گشتی بڵاو مەکەرەوە.'), ('cybersecurity-4', 'ڕاستی داتا', 'Integrity', 'دڵنیایی دەدات داتا بەبێ مۆڵەت نەگۆڕدرابێت.', 'Keep backups\nReview changes', 'فایلی ڕاهێنان پاشەکەوت بکە.'), ('cybersecurity-5', 'بەردەستبوون', 'Availability', 'سیستەم دەبێت کاتێک پێویستە بەردەست بێت.', 'Backup important files\nTest restore', 'پاشەکەوتەکان تاقی بکەرەوە.'), ('cybersecurity-6', 'دوو هەنگاوی پشتڕاستکردنەوە', '2FA', '2FA هەنگاوێکی زیادەی پاراستنە بۆ هەژمارەکان.', 'Enable 2FA in account settings', 'کۆدی پشتڕاستکردنەوە بە هیچ کەس مەدە.'), ('cybersecurity-7', 'فیشینگ', 'Phishing', 'فیشینگ هەوڵی فریودانە بۆ وەرگرتنی زانیاریی نهێنی.', 'Check sender and domain\nAvoid unexpected links', 'پەیامی گومانلێکراو ڕاپۆرت بکە.'), ('cybersecurity-8', 'نوێکردنەوە', 'Updates', 'نوێکردنەوە زۆرجار کەلێنی ئاسایشی چارەسەر دەکات.', 'Update Android and apps', 'نوێکردنەوە دوا مەخە.'), ('cybersecurity-9', 'مۆڵەتی ئەپ', 'App permissions', 'تەنها مۆڵەتی پێویست بە ئەپ بدە.', 'Review camera, mic, location permissions', 'مۆڵەتی ناپێویست لاببە.'), ('cybersecurity-10', 'پاراستنی Wi-Fi', 'Wi-Fi safety', 'WPA2/WPA3 و وشەی نهێنیی بەهێز گرنگن.', 'Use WPA2/WPA3\nChange default router password', 'تەنها ڕاوتەری خۆت ڕێک بخە.'), ('cybersecurity-11', 'پاراستنی مۆبایل', 'Mobile security', 'قوفڵی شاشە، نوێکردنەوە و سەرچاوەی متمانەپێکراو بنەمان.', 'Screen lock\nTrusted app sources', 'فایلی نەناسراو مەکەرەوە.'), ('cybersecurity-12', 'Backup', 'پاشەکەوت', 'پاشەکەوت داتا لە ونبوون دەپارێزێت.', 'Keep a second copy\nTest restore', 'پاشەکەوتی فایلە گرنگەکانت هەبێت.'), ('cybersecurity-13', 'هەڵسەنگاندنی مەترسی', 'Risk', 'مەترسی بە ئەگەری ڕوودان و کاریگەری هەڵدەسەنگێنرێت.', 'Asset -> Threat -> Impact -> Mitigation', 'نموونەی خەیاڵی بنووسە.'), ('cybersecurity-14', 'ڕووداوی ئاسایشی', 'Incident response', 'کاتێک گومان لە ڕووداوێک هەیە، هەژمار بپارێزە و یارمەتیی فەرمی وەربگرە.', 'Review sessions\nChange password from trusted device', 'ڕووداوەکە مەشارەوە.'), ('cybersecurity-15', 'پاراستنی داتا', 'Data protection', 'داتای کەمتر کۆبکەرەوە و دەستگەیشتن سنووردار بکە.', 'Data minimization\nAccess control', 'داتای هەستیار هاوبەش مەکە.')]}, {'id': 'osint', 'name': 'OSINT', 'icon': '🔎', 'intro': 'توێژینەوە بە زانیاریی گشتی و سەرچاوە کراوەکان بە ڕێزگرتن لە تایبەتمەندی.', 'lessons': [('osint-1', 'OSINT چییە؟', 'زانیاریی سەرچاوە کراوە', 'OSINT واتە کۆکردنەوە و هەڵسەنگاندنی زانیارییە گشتییەکان لە سەرچاوە یاسایی و کراوەکان. تەنها لەسەر خۆت، دامەزراوەی ڕازیبوو یان بابەتی گشتی کار بکە.', 'Research notes:\n- Record the source\n- Record the date\n- Verify with another source\n- Separate fact from assumption', 'زانیاریی تایبەتی کەسان، شوێنی نیشتەجێبوون، ژمارە و هەژمارە نهێنییەکان مەکۆڵەوە و بڵاویان مەکەرەوە.'), ('osint-2', 'پشتڕاستکردنەوەی سەرچاوە', 'هەڵسەنگاندنی هەواڵ', 'ناوی نووسەر، بەروار، سەرچاوەی سەرەکی و پشتگیریی سەرچاوەی تر بپشکنە. وێنە یان هەواڵێک بە تەنها بەڵگەی تەواو نییە.', 'Verification checklist:\n1. Who published it?\n2. When was it published?\n3. Is there a primary source?\n4. Do independent sources confirm it?', 'ئەنجامی نادڵنیا وەک ڕاستی بڵاو مەکەرەوە.'), ('osint-3', 'پرسیاری توێژینەوە', 'Research question', 'پێش گەڕان پرسیارێکی دیاریکراو بنووسە.', 'Question / Scope / Date', 'بابەتی گشتی هەڵبژێرە.'), ('osint-4', 'سەرچاوەی سەرەکی', 'Primary sources', 'سەرچاوەی سەرەکی وەک ڕاگەیاندنی فەرمی گرنگە.', 'Find original announcement', 'بەروار و نووسەر تۆمار بکە.'), ('osint-5', 'پشتڕاستکردنەوە', 'Cross-check', 'زانیاری لە دوو سەرچاوەی سەربەخۆدا بەراورد بکە.', 'Compare independent sources', 'ئەنجامی نادڵنیا دیاری بکە.'), ('osint-6', 'بەروار و کات', 'Timeline', 'بەرواری بڵاوکردنەوە لە بەرواری ڕووداو جیا بکەرەوە.', 'Record both dates', 'هەڵەی بەروار تۆمار بکە.'), ('osint-7', 'هەڵسەنگاندنی هەواڵ', 'News verification', 'نووسەر، سەرچاوە، بەروار و بەڵگە بپشکنە.', 'Who? When? Evidence?', 'هەواڵی پشتڕاستنەکراو بڵاو مەکەرەوە.'), ('osint-8', 'تۆمارکردنی سەرچاوە', 'Research log', 'هەر دۆزینەوەیەک بە لینک، بەروار و دڵنیایی تۆمار بکە.', 'Claim | Source | Date | Confidence', 'ڕێکخستنی تۆمارەکان بەردەوام بکە.'), ('osint-9', 'جیاوازی ڕاستی و گریمانە', 'Fact vs inference', 'ڕاستی بەڵگەی ڕاستەوخۆی هەیە؛ گریمانە لێکدانەوەیە.', 'Fact: source says X\nInference: may mean Y', 'گریمانە وەک ڕاستی مەنووسە.'), ('osint-10', 'هەڵەی بیرکردنەوە', 'Bias', 'تەنها بەڵگەی هاوڕای خۆت مەبینە؛ بەڵگەی دژیش بپشکنە.', 'Look for contrary evidence', 'بێلایەن بمێنە.'), ('osint-11', 'پاراستنی تایبەتمەندی', 'Privacy', 'زانیاری گشتی هەمیشە ڕەزامەندی بۆ کۆکردنەوە نییە.', 'Minimize personal data', 'زانیاری تایبەتی کەسان مەکۆڵەوە.'), ('osint-12', 'ڕاپۆرتنووسی', 'Reporting', 'ڕاپۆرت پرسیار، سەرچاوە، دۆزینەوە و سنوورەکان دەخاتەڕوو.', 'Summary / Sources / Limits', 'زمانی بێلایەن بەکاربهێنە.'), ('osint-13', 'گەڕانی فلتەردار', 'Search filters', 'فلتەری site بۆ دۆزینەوەی بەڵگەی گشتی لە ماڵپەڕێکی دیاریکراوە.', 'site:example.org public report', 'تەنها بابەتی گشتی بگەڕێ.'), ('osint-14', 'کۆنتێکستی وێنە', 'Image context', 'وێنە دەتوانێت کۆن یان لە شوێنێکی تر بێت؛ سەرچاوەی سەرەکی بپشکنە.', 'Find original public post', 'وێنەی کەسانی تایبەتی بۆ شوێنکەوتن بەکارمەهێنە.'), ('osint-15', 'ڕاهێنانی وانەی 15', 'پێداچوونەوە و ڕاهێنان', 'ئەم وانەیە بۆ پێداچوونەوەی بابەتەکانی پێشووە. زانیارییەکان بە نموونەی خۆت تاقی بکەرەوە و هەڵەکانت تۆمار بکە.', 'Review your notes\nPractice with your own example', 'لە ژینگەی خۆت و بە شێوەی یاسایی ڕاهێنان بکە.')]}, {'id': 'ethical-hacking', 'name': 'Ethical Hacking', 'icon': '🧪', 'intro': 'تاقیکردنەوەی پاراستن تەنها لە تۆڕ و ئامێری خۆت یان لەگەڵ مۆڵەتی نووسراو.', 'lessons': [('eh-1', 'یاسا و مۆڵەت', 'پێش هەر تاقیکردنەوەیەک', 'Ethical Hacking بۆ دۆزینەوە و چارەسەرکردنی لاوازییەکانە. تاقیکردنەوەی سیستەمی کەسانی تر بەبێ مۆڵەت ڕێگەپێدراو نییە.', 'Safe lab rules:\n- Use your own device or an authorized lab\n- Define the scope\n- Do not access real user data\n- Stop if you leave the approved scope\n- Report findings responsibly', 'بۆ دەستپێک، تەنها لە ژینگەی ڕاهێنانی خۆجێیی و یاسایی کار بکە.'), ('eh-2', 'ڕەوتی تاقیکردنەوە', 'پلان، تاقیکردنەوە، ڕاپۆرت', 'ڕەوتی گشتی بریتییە لە دیاریکردنی مەودا، تێگەیشتن لە سیستەم، تاقیکردنەوەی سنووردار، تۆمارکردنی دۆزینەوە و پێشنیاری چارەسەر.', 'Report template:\n- Scope and permission\n- Date and environment\n- Finding summary\n- Potential impact\n- Recommended fix', 'هیچ زانیارییەکی نهێنی لە ڕاپۆرتدا مەخەرەڕوو.'), ('ethical-hacking-3', 'مۆڵەت و مەودا', 'Scope', 'مۆڵەت دەبێت ئامێر، کات و جۆری تاقیکردنەوە دیاری بکات.', 'Owner / Targets / Time / Allowed tests', 'ئەگەر مەودا ڕوون نییە، تاقیکردنەوە مەکە.'), ('ethical-hacking-4', 'لابراتواری فێربوون', 'Safe lab', 'ژینگەی خۆجێیی و لابراتواری ڕاهێنان بۆ فێربوون بەکاربهێنە.', 'Use your own isolated lab', 'داتای ڕاستەقینەی کەسانی تر بەکارمەهێنە.'), ('ethical-hacking-5', 'ڕەوتی کار', 'Methodology', 'پلان، مۆڵەت، تاقیکردنەوەی سنووردار، ڕاپۆرت و چارەسەر.', 'Plan -> Test -> Report -> Fix', 'هەر هەنگاوێک لە مەودای مۆڵەتدا بێت.'), ('ethical-hacking-6', 'دارایی دیجیتاڵ', 'Assets', 'داتا، هەژمار و سێرڤەر دارایی دیجیتاڵن و پێویستیان بە پاراستنە.', 'List assets you own', 'تەنها دارایی خۆت تۆمار بکە.'), ('ethical-hacking-7', 'هەڕەشە و لاوازی', 'Threat and weakness', 'هەڕەشە هۆکاری زیانە و لاوازی کەلێنێکی پاراستنە.', 'Asset / Threat / Weakness / Impact', 'نموونەی خەیاڵی بنووسە.'), ('ethical-hacking-8', 'هەڵسەنگاندنی مەترسی', 'Risk', 'مەترسی بە ئەگەری ڕوودان و کاریگەری هەڵدەسەنگێنرێت.', 'Likelihood x Impact', 'ڕێکاری کەمکردنەوە بنووسە.'), ('ethical-hacking-9', 'پشکنینی ڕێکخستن', 'Configuration review', 'پێداچوونەوە بە مۆڵەت، نوێکردنەوە و هەژمارە بەکارهاتووەکان گرنگە.', 'Review your own app settings', 'تەنها سیستەمی خۆت بپشکنە.'), ('ethical-hacking-10', 'پاراستنی وێب', 'Web defense', 'HTTPS، پشتڕاستکردنەوە و پاراستنی session بنەمای پاراستنی وێبن.', 'Use HTTPS\nValidate inputs\nProtect sessions', 'لە پرۆژەی خۆتدا تاقی بکەرەوە.'), ('ethical-hacking-11', 'ڕاپۆرتی دۆزینەوە', 'Finding report', 'ڕاپۆرت کورتە، کاریگەری، بەڵگەی ناهەستیار و چارەسەر دەگرێتەوە.', 'Title / Impact / Evidence / Fix', 'وشەی نهێنی لە ڕاپۆرتدا مەخەرەڕوو.'), ('ethical-hacking-12', 'چارەسەرکردن', 'Remediation', 'دۆزینەوە بە پێشنیاری چارەسەری کردارپێکراو بەسوود دەبێت.', 'Patch / Safer config / Least privilege', 'چارەسەر لە ژینگەی تاقیکردنەوە تاقی بکەرەوە.'), ('ethical-hacking-13', 'پشکنینی دووبارە', 'Retesting', 'دوای چارەسەرکردن پشکنین بکە بۆ دڵنیایی لە چارەسەر.', 'Record before and after', 'تەنها لە سیستەمی مۆڵەتپێدراو.'), ('ethical-hacking-14', 'ڕەفتاری پیشەیی', 'Professional conduct', 'ڕاستگۆیی، پاراستنی نهێنی و ڕاپۆرتکردنی بەرپرسانە گرنگن.', 'Respect scope\nProtect evidence', 'ئەگەر هەڵە ڕوویدا، ڕاستگۆ بە.'), ('ethical-hacking-15', 'ڕاهێنانی وانەی 15', 'پێداچوونەوە و ڕاهێنان', 'ئەم وانەیە بۆ پێداچوونەوەی بابەتەکانی پێشووە. زانیارییەکان بە نموونەی خۆت تاقی بکەرەوە و هەڵەکانت تۆمار بکە.', 'Review your notes\nPractice with your own example', 'لە ژینگەی خۆت و بە شێوەی یاسایی ڕاهێنان بکە.')]}, {'id': 'networking', 'name': 'Networking', 'icon': '🌐', 'intro': 'بنەماکانی IP، DNS، HTTP و تۆڕ.', 'lessons': [('net-1', 'IP و DNS', 'ناونیشانی تۆڕ', 'IP ناونیشانی ئامێر لە تۆڕە. DNS ناوی دۆمەین بە ناونیشانی IP دەگۆڕێت.', 'Example:\nDomain: example.com\nDNS: translates a domain name to an IP address', 'ئەمە تەنها بنەمای تیۆرییە؛ هیچ تۆڕێکی تر مەپشکنە بەبێ مۆڵەت.'), ('net-2', 'HTTP و HTTPS', 'پەیوەندیی وێب', 'HTTP بۆ گواستنەوەی داواکاری و وەڵامی وێب بەکاردێت. HTTPS پەیوەندییەکە بە TLS پارێزراوتر دەکات.', 'Browser -> HTTPS request -> Web server -> Response', 'لە وێبسایتە گرنگەکاندا نیشانەی قوفڵ و ناونیشانی دروست بپشکنە.'), ('networking-3', 'LAN و WAN', 'جۆرەکانی تۆڕ', 'LAN تۆڕی ناوخۆییە؛ WAN ناوچەیەکی فراوانتر دەگرێتەوە.', 'LAN: home network\nWAN: internet', 'نەخشەی تۆڕی ماڵەوە بکێشە.'), ('networking-4', 'MAC address', 'ناونیشانی interface', 'MAC ناسنامەی interface ـی تۆڕە.', 'ip link', 'تەنها ئامێری خۆت بپشکنە.'), ('networking-5', 'Router و Switch', 'ئامێرەکانی تۆڕ', 'Switch ئامێرە ناوخۆییەکان پەیوەست دەکات؛ router تۆڕەکان پەیوەست دەکات.', 'Phone -> Router -> Internet', 'ڕاوتەری خۆت بناسە.'), ('networking-6', 'DHCP', 'دابەشکردنی IP', 'DHCP بە شێوەی ئۆتۆماتیکی IP بە ئامێر دەدات.', 'Check device network settings', 'ڕاوتەری خۆت ڕێک بخە.'), ('networking-7', 'TCP و UDP', 'پڕۆتۆکۆڵ', 'TCP پەیوەندیی دڵنیاترە؛ UDP بۆ هەندێ کاری کەم-دواکەوتن بەکاردێت.', 'TCP: reliable stream\nUDP: datagrams', 'جیاوازییان فێربە.'), ('networking-8', 'Port', 'دەرچە', 'Port ژمارەیەکە کە خزمەتگوزاری لە ئامێرێکدا دیاری دەکات.', '80 HTTP\n443 HTTPS', 'ژمارەکان بۆ تێگەیشتن فێربە.'), ('networking-9', 'HTTP و HTTPS', 'پەیوەندی وێب', 'HTTPS پەیوەندیی وێب بە TLS پارێزراوتر دەکات.', 'Browser -> HTTPS -> Server', 'ناونیشانی وێبسایت بپشکنە.'), ('networking-10', 'Latency', 'دواکەوتنی پەیوەندی', 'Latency ماوەی گەڕانەوەی داتایە.', 'ping -c 3 127.0.0.1', 'localhost تەنها ئامێری خۆتە.'), ('networking-11', 'Firewall', 'دیوارە ئاگرین', 'Firewall هاتووچۆی تۆڕ بە یاسای دیاریکراو ڕێک دەخات.', 'Allow only needed services', 'ڕێکخستنی firewall بەبێ تێگەیشتن مەگۆڕە.'), ('networking-12', 'پاراستنی Wi-Fi', 'WPA2 و WPA3', 'وشەی نهێنیی بەهێز و WPA2/WPA3 پاراستنی Wi-Fi باشتر دەکەن.', 'Use WPA2/WPA3', 'تەنها ڕاوتەری خۆت ڕێک بخە.'), ('networking-13', 'چارەسەری کێشە', 'Troubleshooting', 'هەنگاو بە هەنگاو Wi-Fi، IP، DNS و پەیوەندی بپشکنە.', 'Check Wi-Fi\nCheck IP\nCheck DNS', 'ئەنجامی هەر هەنگاو تۆمار بکە.'), ('networking-14', 'نەخشەی تۆڕ', 'Network diagram', 'نەخشەی تۆڕ ئامێر و پەیوەندییەکان بە شێوەی ڕوون پیشان دەدات.', 'Draw phone, router, internet', 'تۆڕی ماڵەوەی خۆت بکێشە.'), ('networking-15', 'ڕاهێنانی وانەی 15', 'پێداچوونەوە و ڕاهێنان', 'ئەم وانەیە بۆ پێداچوونەوەی بابەتەکانی پێشووە. زانیارییەکان بە نموونەی خۆت تاقی بکەرەوە و هەڵەکانت تۆمار بکە.', 'Review your notes\nPractice with your own example', 'لە ژینگەی خۆت و بە شێوەی یاسایی ڕاهێنان بکە.')]}]

TOOL_GROUPS = {'Linux (١٥ فەرمان)': [('pwd', 'شوێنی فۆڵدەری ئێستا', 'pwd'), ('ls', 'بینینی فایلەکان', 'ls -lah'), ('cd', 'گۆڕینی فۆڵدەر', 'cd ~/Documents'), ('mkdir', 'دروستکردنی فۆڵدەر', 'mkdir practice'), ('touch', 'دروستکردنی فایل', 'touch note.txt'), ('cp', 'کۆپیکردنی فایل', 'cp note.txt copy.txt'), ('mv', 'گواستنەوە یان گۆڕینی ناو', 'mv copy.txt backup.txt'), ('cat', 'خوێندنەوەی فایل', 'cat note.txt'), ('less', 'خوێندنەوەی فایلێکی درێژ', 'less note.txt'), ('grep', 'گەڕان لە ناو دەق', "grep -n 'Linux' note.txt"), ('find', 'دۆزینەوەی فایل لە فۆڵدەری خۆت', "find . -name '*.txt'"), ('nano', 'دەستکاریکردنی دەق', 'nano note.txt'), ('df', 'شوێنی دیسک', 'df -h'), ('du', 'قەبارەی فۆڵدەر', 'du -sh .'), ('tar', 'ئەرشیڤی فایلەکانی ڕاهێنان', 'tar -czf backup.tar.gz practice')], 'Termux (١٥ فەرمان)': [('pkg update', 'نوێکردنەوەی لیستی پەکەج', 'pkg update'), ('pkg upgrade', 'نوێکردنەوەی پەکەجەکان', 'pkg upgrade'), ('pkg search', 'گەڕان بۆ پەکەج', 'pkg search python'), ('pkg show', 'زانیاریی پەکەج', 'pkg show python'), ('pkg install', 'دامەزراندنی پەکەج', 'pkg install python'), ('pkg list-installed', 'بینینی پەکەجە دامەزراوەکان', 'pkg list-installed'), ('termux-info', 'زانیاریی Termux', 'termux-info'), ('termux-setup-storage', 'داوای مۆڵەتی فایلەکانی Android', 'termux-setup-storage'), ('termux-change-repo', 'گۆڕینی mirror ـی پەکەج', 'termux-change-repo'), ('termux-wake-lock', 'پاراستنی بیداربوونی Termux لە کاتی کار', 'termux-wake-lock'), ('termux-wake-unlock', 'لابردنی wake lock', 'termux-wake-unlock'), ('termux-open', 'کردنەوەی فایل بە ئەپی گونجاو', 'termux-open note.txt'), ('termux-clipboard-get', 'خوێندنەوەی کلیپبۆرد، ئەگەر بەردەست بێت', 'termux-clipboard-get'), ('termux-clipboard-set', 'دانانی دەق لە کلیپبۆرد', "echo 'Hello' | termux-clipboard-set"), ('exit', 'دەرچوون لە shell', 'exit')], 'Python (١٠ ئامراز)': [('python', 'جێبەجێکردنی سکریپت', 'python main.py'), ('pip', 'پشکنینی pip', 'python -m pip --version'), ('venv', 'ژینگەی جیاوازی پرۆژە', 'python -m venv .venv'), ('REPL', 'تاقیکردنەوەی Python', 'python'), ('unittest', 'تاقیکردنەوەی کۆد', 'python -m unittest'), ('json', 'کارکردن لەگەڵ JSON', 'python -c "import json; print(json.dumps({\'ok\': True}))"'), ('pathlib', 'ڕێڕەوی فایل', 'python -c "from pathlib import Path; print(Path.cwd())"'), ('http.server', 'سێرڤەری ناوخۆیی فایل', 'python -m http.server 8080'), ('compileall', 'پشکنینی syntax', 'python -m compileall .'), ('help', 'یارمەتیی Python', 'python -c "help(\'print\')"')], 'C++ (١٠ ئامراز)': [('clang++', 'کۆمپایلەری C++', 'clang++ main.cpp -o main'), ('g++', 'کۆمپایلەری GNU، ئەگەر دامەزراوە', 'g++ main.cpp -o main'), ('make', 'جێبەجێکردنی Makefile', 'make'), ('cmake', 'پشکنینی CMake', 'cmake --version'), ('gdb', 'پشکنینی debugger', 'gdb --version'), ('clang-format', 'ڕێکخستنی شێوازی کۆد', 'clang-format --version'), ('compiler version', 'پشکنینی وەشان', 'clang++ --version'), ('compile', 'کۆمپایلکردنی فایل', 'clang++ main.cpp -o app'), ('run', 'جێبەجێکردنی بەرنامەی خۆت', './app'), ('warnings', 'ئاگادارکردنەوەی compiler', 'clang++ -Wall -Wextra main.cpp -o app')], 'Networking (١٠ ئامراز)': [('ip', 'بینینی interface ـی خۆت', 'ip addr'), ('ping localhost', 'تاقیکردنەوەی localhost', 'ping -c 3 127.0.0.1'), ('getent', 'پشکنینی DNS بۆ دۆمەینی گشتی', 'getent hosts example.com'), ('nslookup', 'پشکنینی DNS', 'nslookup example.com'), ('dig', 'زانیاریی DNS', 'dig example.com'), ('curl', 'وەرگرتنی سەردێڕی پەڕەی گشتی', 'curl -I https://example.com'), ('traceroute', 'ڕێڕەوی تۆڕ بۆ ئامانجی ڕێگەپێدراو', 'traceroute example.com'), ('ss', 'پەیوەندییەکانی ئامێری خۆت', 'ss -tuln'), ('hostname', 'ناوی ئامێر', 'hostname'), ('ip route', 'ڕێڕەوی تۆڕی خۆت', 'ip route')], 'Security & Privacy (١٠ ئامراز)': [('sha256sum', 'پشکنینی hash ـی فایلەکانی خۆت', 'sha256sum note.txt'), ('openssl', 'پشکنینی وەشانی OpenSSL', 'openssl version'), ('gpg', 'پشکنینی GPG', 'gpg --version'), ('ufw status', 'بینینی دۆخی firewall لە سیستەمی پشتگیریکراو', 'ufw status'), ('whoami', 'ناسینی بەکارهێنەری ئێستا', 'whoami'), ('id', 'ناسینی UID و گرووپ', 'id'), ('last', 'تۆماری چوونەژوورەوە لە سیستەمی خۆت', 'last'), ('journalctl', 'خوێندنەوەی لۆگی سیستەم', 'journalctl -n 20'), ('passwd', 'گۆڕینی وشەی نهێنی هەژماری خۆت', 'passwd'), ('umask', 'بینینی مۆڵەتی بنەڕەتی فایل', 'umask')]}

def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db_connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS posts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS progress(
            user_id INTEGER NOT NULL,
            lesson_id TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            PRIMARY KEY(user_id, lesson_id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")

def get_lesson(lesson_id):
    for course in LESSONS:
        for lesson in course["lessons"]:
            if lesson[0] == lesson_id:
                return course, lesson
    return None, None

@app.before_request
def csrf_check():
    session.setdefault("csrf_token", secrets.token_hex(24))
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(supplied, expected):
            abort(400)

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

BASE = r"""
<!doctype html>
<html lang="ku" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} | CYBER KURD</title>
<style>
:root{--bg:#070d12;--panel:#101c25;--line:#24404a;--green:#00e6a0;--muted:#9bb0ba;--white:#edf7fa}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--white);font-family:Tahoma,Arial,sans-serif;line-height:1.85}
a{color:var(--green);text-decoration:none}
header{background:#0d1820;border-bottom:1px solid var(--line);padding:14px 5%;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.logo{font-size:23px;font-weight:bold;color:var(--green);direction:ltr}
nav{display:flex;gap:13px;align-items:center;flex-wrap:wrap}
nav a{font-size:14px}
main{max-width:1000px;margin:25px auto;padding:0 16px;min-height:70vh}
.hero,.card{background:var(--panel);border:1px solid var(--line);border-radius:15px;padding:20px;margin:15px 0}
.hero{background:linear-gradient(135deg,#0c2827,#10202c);padding:28px}
h1,h2,h3{color:var(--green);line-height:1.5}
h1{font-size:30px}
button,.btn{background:#00c98b;color:#04130e;border:0;border-radius:9px;padding:10px 17px;font-weight:bold;cursor:pointer;display:inline-block;font-size:14px}
input,textarea,select{width:100%;background:#071118;color:white;border:1px solid #34505c;border-radius:8px;padding:12px;margin:7px 0 15px;font:inherit}
textarea{min-height:125px}
label{display:block;color:#c9d8de}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
.muted{color:var(--muted);font-size:13px}
.tag{display:inline-block;background:#153d37;color:var(--green);padding:3px 10px;border-radius:20px;font-size:12px}
pre{direction:ltr;text-align:left;white-space:pre-wrap;overflow-wrap:anywhere;background:#050b10;border:1px solid #263b46;border-radius:9px;padding:14px;color:#9cf5ce;overflow-x:auto}
.content{white-space:pre-wrap;overflow-wrap:anywhere}
.msg{background:#172832;border-radius:9px;padding:12px;margin:10px 0}
.error{color:#ff8585}
.success{color:#71edb6}
hr{border:0;border-top:1px solid var(--line);margin:18px 0}
footer{text-align:center;color:var(--muted);padding:25px}
@media(max-width:560px){header{padding:12px}nav{gap:9px}.logo{font-size:19px}h1{font-size:24px}}
</style>
</head>
<body>
<header>
 <div class="logo">⚡ CYBER KURD</div>
 <nav>
  <a href="{{ url_for('home') }}">سەرەکی</a>
  <a href="{{ url_for('academy') }}">ئەکادیمیا</a>
  <a href="{{ url_for('toolbox') }}">ئامرازەکان</a>
  <a href="{{ url_for('commands') }}">فەرمانەکان</a>
  <a href="{{ url_for('community') }}">کۆمەڵگە</a>
  <a href="{{ url_for('chat') }}">چات</a>
  {% if user %}
   <span class="muted">{{ user }}</span>
   <form method="post" action="{{ url_for('logout') }}" style="margin:0">
    <input type="hidden" name="csrf_token" value="{{ csrf }}">
    <button>چوونەدەرەوە</button>
   </form>
  {% else %}
   <a href="{{ url_for('login') }}">چوونەژوورەوە</a>
   <a href="{{ url_for('register') }}">ئەکاونت دروست بکە</a>
  {% endif %}
 </nav>
</header>
<main>
{% with notices=get_flashed_messages() %}
 {% if notices %}<div class="card success">{% for n in notices %}<div>{{ n }}</div>{% endfor %}</div>{% endif %}
{% endwith %}
{{ body }}
</main>
<footer>CYBER KURD • فێربە، هاوبەشی بکە، پارێزگاری بکە</footer>
</body></html>
"""

def render_page(title, template, **kwargs):
    body = render_template_string(template, **kwargs)
    return render_template_string(
        BASE, title=title, body=Markup(body),
        user=session.get("username"), csrf=session.get("csrf_token")
    )

@app.route("/")
def home():
    with db_connect() as db:
        posts = db.execute("""SELECT p.*,u.username FROM posts p
            JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 5""").fetchall()
        count = db.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
    return render_page("سەرەکی", """
    <section class="hero">
      <h1>⚡ بەخێربێیت بۆ CYBER KURD</h1>
      <p>پلاتفۆرمێکی کوردی بۆ فێربوونی Linux، Termux، Python، C++، OSINT و Cybersecurity.</p>
      <p>فێربە، ڕاهێنان بکە، زانیاری هاوبەش بکە و بە شێوەی یاسایی پاراستن فێربە.</p>
      <a class="btn" href="{{ url_for('academy') }}">دەستپێکردنی فێربوون</a>
    </section>
    <div class="grid">
      <div class="card"><h3>📚 وانەکان</h3><p>وانەی هەنگاو بە هەنگاو بە زمانی کوردی.</p></div>
      <div class="card"><h3>🧰 ئامرازەکان</h3><p>ئامرازەکانی Linux، Termux، Python، C++ و تۆڕ.</p><a href="{{ url_for('toolbox') }}">بینینی ئامرازەکان</a></div>
      <div class="card"><h3>⌨️ فەرمانەکانی Termux</h3><p>فەرمانەکان، ئەرکیان و نموونەی بەکارهێنان.</p><a href="{{ url_for('commands') }}">بینینی فەرمانەکان</a></div>
      <div class="card"><h3>💬 کۆمەڵگە و چات</h3><p>بابەت بڵاو بکەرەوە و لەگەڵ ئەندامان گفتوگۆ بکە.</p></div>
    </div>
    <div class="card"><h2>ئەندامان</h2><h1>{{ count }}</h1><span class="muted">ئەکاونتی تۆمارکراو</span></div>
    <h2>نوێترین بابەتەکان</h2>
    {% for p in posts %}
      <div class="card"><span class="tag">{{ p.category }}</span><h3>{{ p.title }}</h3>
      <p class="content">{{ p.content }}</p><span class="muted">نووسەر: {{ p.username }} • {{ p.created_at }}</span></div>
    {% else %}<div class="card">هێشتا بابەتێک نییە.</div>{% endfor %}
    """, posts=posts, count=count)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_]{3,24}", username):
            error = "ناوی بەکارهێنەر دەبێت ٣ تا ٢٤ پیت و ژمارە بێت."
        elif len(password) < 10:
            error = "وشەی نهێنی دەبێت لانیکەم ١٠ پیت بێت."
        else:
            try:
                with db_connect() as db:
                    cur = db.execute("INSERT INTO users(username,password,created_at) VALUES(?,?,?)",
                        (username, generate_password_hash(password), now()))
                    session.clear()
                    session["user_id"] = cur.lastrowid
                    session["username"] = username
                    session["csrf_token"] = secrets.token_hex(24)
                return redirect(url_for("academy"))
            except sqlite3.IntegrityError:
                error = "ئەم ناوی بەکارهێنەرە پێشتر بەکارهاتووە."
    return render_page("تۆمارکردن", """
    <div class="card"><h2>دروستکردنی ئەکاونت</h2><p class="error">{{ error }}</p>
    <form method="post"><input type="hidden" name="csrf_token" value="{{ csrf }}">
    <label>ناوی بەکارهێنەر (ئینگلیزی)</label><input name="username" minlength="3" maxlength="24" required>
    <label>وشەی نهێنی (لانیکەم ١٠ پیت)</label><input type="password" name="password" minlength="10" required>
    <button>دروستکردنی ئەکاونت</button></form><p><a href="{{ url_for('login') }}">ئەکاونتم هەیە</a></p></div>
    """, error=error)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db_connect() as db:
            u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if u and check_password_hash(u["password"], password):
            session.clear()
            session["user_id"] = u["id"]
            session["username"] = u["username"]
            session["csrf_token"] = secrets.token_hex(24)
            return redirect(url_for("academy"))
        error = "ناوی بەکارهێنەر یان وشەی نهێنی هەڵەیە."
    return render_page("چوونەژوورەوە", """
    <div class="card"><h2>چوونەژوورەوە</h2><p class="error">{{ error }}</p>
    <form method="post"><input type="hidden" name="csrf_token" value="{{ csrf }}">
    <label>ناوی بەکارهێنەر</label><input name="username" required>
    <label>وشەی نهێنی</label><input type="password" name="password" required>
    <button>چوونەژوورەوە</button></form></div>
    """, error=error)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/academy")
def academy():
    progress = set()
    if session.get("user_id"):
        with db_connect() as db:
            rows = db.execute("SELECT lesson_id FROM progress WHERE user_id=?", (session["user_id"],)).fetchall()
            progress = {r["lesson_id"] for r in rows}
    return render_page("ئەکادیمیا", """
    <h1>ئەکادیمیای CYBER KURD</h1>
    <p>بابەتێک هەڵبژێرە و وانەکان بە ڕیز بخوێنەوە.</p>
    <div class="grid">
    {% for c in courses %}
      <div class="card"><h2>{{ c.icon }} {{ c.name }}</h2><p>{{ c.intro }}</p>
      <p class="muted">{{ c.lessons|length }} وانە • {{ c.lessons|selectattr(0,'in',progress)|list|length }} تەواوکراو</p>
      <a class="btn" href="{{ url_for('course', course_id=c.id) }}">بینینی وانەکان</a></div>
    {% endfor %}
    </div>
    """, courses=LESSONS, progress=progress)

@app.route("/course/<course_id>")
def course(course_id):
    course = next((c for c in LESSONS if c["id"] == course_id), None)
    if not course:
        abort(404)
    done = set()
    if session.get("user_id"):
        with db_connect() as db:
            done = {r["lesson_id"] for r in db.execute(
                "SELECT lesson_id FROM progress WHERE user_id=?", (session["user_id"],)).fetchall()}
    return render_page(course["name"], """
    <h1>{{ course.icon }} {{ course.name }}</h1><p>{{ course.intro }}</p>
    {% for l in course.lessons %}
      <div class="card"><span class="tag">وانە {{ loop.index }}</span>
      <h3>{{ l[1] }}</h3><p>{{ l[2] }}</p>
      {% if l[0] in done %}<span class="success">✓ تەواوکراوە</span>{% endif %}
      <p><a class="btn" href="{{ url_for('lesson', lesson_id=l[0]) }}">کردنەوەی وانە</a></p></div>
    {% endfor %}
    """, course=course, done=done)

@app.route("/lesson/<lesson_id>")
def lesson(lesson_id):
    course, lesson_data = get_lesson(lesson_id)
    if not lesson_data:
        abort(404)
    completed = False
    if session.get("user_id"):
        with db_connect() as db:
            completed = db.execute("SELECT 1 FROM progress WHERE user_id=? AND lesson_id=?",
                (session["user_id"], lesson_id)).fetchone() is not None
    return render_page(lesson_data[1], """
    <p><a href="{{ url_for('course', course_id=course.id) }}">← گەڕانەوە بۆ {{ course.name }}</a></p>
    <div class="card"><span class="tag">{{ course.name }}</span><h1>{{ lesson[1] }}</h1>
    <h3>{{ lesson[2] }}</h3><p class="content">{{ lesson[3] }}</p>
    <h3>نموونە / فەرمان</h3><pre>{{ lesson[4] }}</pre>
    <h3>تێبینی</h3><p>{{ lesson[5] }}</p>
    {% if user_id %}
      {% if completed %}<p class="success">✓ ئەم وانەیە تەواو کراوە</p>{% else %}
      <form method="post" action="{{ url_for('complete_lesson', lesson_id=lesson[0]) }}">
       <input type="hidden" name="csrf_token" value="{{ csrf }}"><button>نیشانکردن وەک تەواوکراو</button>
      </form>{% endif %}
    {% else %}<p><a href="{{ url_for('login') }}">بچۆ ژوورەوە</a> بۆ تۆمارکردنی پێشکەوتنت.</p>{% endif %}
    </div>
    """, course=course, lesson=lesson_data, completed=completed, user_id=session.get("user_id"))

@app.route("/complete/<lesson_id>", methods=["POST"])
@login_required
def complete_lesson(lesson_id):
    course, lesson_data = get_lesson(lesson_id)
    if not lesson_data:
        abort(404)
    with db_connect() as db:
        db.execute("INSERT OR IGNORE INTO progress(user_id,lesson_id,completed_at) VALUES(?,?,?)",
            (session["user_id"], lesson_id, now()))
    flash("وانەکە وەک تەواوکراو تۆمار کرا.")
    return redirect(url_for("lesson", lesson_id=lesson_id))

@app.route("/tools")
def toolbox():
    return render_page("ئامراز و فەرمانەکان", """
    <h1>🧰 ئامراز و فەرمانەکان</h1>
    <p>هەر ئامرازێک بخوێنەوە، بزانە بۆ چییە، پاشان فەرمانەکە لە Termux یان ژینگەی گونجاودا تاقی بکەرەوە.</p>
    {% for group, items in groups.items() %}
      <h2>{{ group }}</h2>
      <div class="grid">
      {% for t in items %}
        <div class="card"><h3>{{ t[0] }}</h3><p>{{ t[1] }}</p><pre>{{ t[2] }}</pre></div>
      {% endfor %}
      </div>
    {% endfor %}
    <div class="card"><h3>ئاگاداریی گرنگ</h3>
    <p>فەرمانەکانی تۆڕ تەنها لەسەر ئامێر و تۆڕی خۆت یان بە مۆڵەتی ڕوون بەکاربهێنە. فەرمانی نەناسراو یان سڕینەوە پێش تێگەیشتن جێبەجێ مەکە.</p></div>
    """, groups=TOOL_GROUPS)

@app.route("/commands")
def commands():
    return render_page("فەرمانەکانی Termux", """
    <h1>⌨️ ١٥ فەرمانی گرنگی Termux</h1>
    <p>ئەم فەرمانانە لە Termux ـدا بەکاردێن. نموونەکان لە فۆڵدەری ڕاهێنان تاقی بکەرەوە.</p>
    {% for t in groups['Termux (١٥ فەرمان)'] %}
      <div class="card"><h3>{{ t[0] }}</h3><p>{{ t[1] }}</p><pre>{{ t[2] }}</pre></div>
    {% endfor %}
    <div class="card"><h3>چۆن فەرمانەکە جێبەجێ بکەم؟</h3>
      <ol><li>فەرمانەکە بخوێنەوە و مەبەستی تێبگە.</li><li>کۆپی بکە و لە Termux دایبنێ.</li><li>Enter بکە و دەرئەنجامەکە بخوێنەوە.</li><li>ئەگەر داوای مۆڵەت یان پشتڕاستکردنەوەی کرد، پێش بەڵێگوتن تێبگە.</li></ol>
    </div>
    """, groups=TOOL_GROUPS)

@app.route("/community")
def community():
    with db_connect() as db:
        posts = db.execute("""SELECT p.*,u.username FROM posts p
            JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 100""").fetchall()
    return render_page("کۆمەڵگە", """
    <h1>کۆمەڵگەی CYBER KURD</h1>
    {% if user %}<a class="btn" href="{{ url_for('new_post') }}">+ بڵاوکردنەوەی بابەت</a>
    {% else %}<p><a href="{{ url_for('login') }}">بچۆ ژوورەوە</a> بۆ بڵاوکردنەوەی بابەت.</p>{% endif %}
    {% for p in posts %}
      <div class="card"><span class="tag">{{ p.category }}</span><h3>{{ p.title }}</h3>
      <p class="content">{{ p.content }}</p><span class="muted">{{ p.username }} • {{ p.created_at }}</span></div>
    {% else %}<div class="card">هێشتا بابەتێک نییە.</div>{% endfor %}
    """, posts=posts)

@app.route("/new-post", methods=["GET", "POST"])
@login_required
def new_post():
    error = ""
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        category = request.form.get("category", "")
        if not 3 <= len(title) <= 100:
            error = "ناونیشان دەبێت ٣ تا ١٠٠ پیت بێت."
        elif not 1 <= len(content) <= 3000:
            error = "ناوەڕۆک دەبێت ١ تا ٣٠٠٠ پیت بێت."
        elif category not in CATEGORIES:
            error = "بابەتێکی دروست هەڵبژێرە."
        else:
            with db_connect() as db:
                db.execute("INSERT INTO posts(user_id,category,title,content,created_at) VALUES(?,?,?,?,?)",
                    (session["user_id"], category, title, content, now()))
            return redirect(url_for("community"))
    return render_page("بابەتی نوێ", """
    <div class="card"><h2>بڵاوکردنەوەی زانیاری</h2><p class="error">{{ error }}</p>
    <form method="post"><input type="hidden" name="csrf_token" value="{{ csrf }}">
    <label>ناونیشان</label><input name="title" maxlength="100" required>
    <label>پۆل</label><select name="category">{% for c in categories %}<option>{{ c }}</option>{% endfor %}</select>
    <label>ناوەڕۆک</label><textarea name="content" maxlength="3000" required></textarea>
    <button>بڵاوکردنەوە</button></form></div>
    """, error=error, categories=CATEGORIES)

@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    if request.method == "POST":
        message = request.form.get("message", "").strip()
        if 1 <= len(message) <= 1000:
            with db_connect() as db:
                db.execute("INSERT INTO messages(user_id,message,created_at) VALUES(?,?,?)",
                    (session["user_id"], message, now()))
        return redirect(url_for("chat"))
    with db_connect() as db:
        messages = db.execute("""SELECT m.*,u.username FROM messages m
            JOIN users u ON u.id=m.user_id ORDER BY m.id DESC LIMIT 100""").fetchall()
    return render_page("چاتی ئەندامان", """
    <h1>💬 چاتی ئەندامان</h1><p class="muted">چاتەکە هاوبەشە؛ بۆ بینینی پەیامی نوێ پەڕەکە نوێ بکەرەوە.</p>
    <div class="card">
    {% for m in messages|reverse %}
      <div class="msg"><strong>{{ m.username }}</strong><p class="content">{{ m.message }}</p><span class="muted">{{ m.created_at }}</span></div>
    {% else %}<p>هێشتا پەیام نییە. یەکەم کەس بە.</p>{% endfor %}
    </div>
    <div class="card"><form method="post"><input type="hidden" name="csrf_token" value="{{ csrf }}">
    <textarea name="message" maxlength="1000" placeholder="پەیامەکەت بنووسە..." required></textarea>
    <button>ناردنی پەیام</button></form></div>
    """, messages=messages)

@app.errorhandler(404)
def not_found(error):
    return render_page("نەدۆزرایەوە", '<div class="card"><h2>ئەم پەڕەیە نەدۆزرایەوە.</h2><a href="/">سەرەکی</a></div>'), 404

@app.errorhandler(400)
def bad_request(error):
    return render_page("هەڵە", '<div class="card"><h2>داواکارییەکە دروست نییە.</h2><a href="/">سەرەکی</a></div>'), 400

if __name__ == "__main__":
    init_db()
    print("====================================")
    print("          CYBER KURD ONLINE")
    print("       http://127.0.0.1:5000")
    print("====================================")
    app.run(host="0.0.0.0", port=5000, debug=False)
