#!/usr/bin/env python3
"""Physical-device UI smoke test. Keeps existing app data; saves screenshots under .tools/frontend.

Install the debug APK and grant microphone/notification access first. Keep SwaraLara
in the foreground and leave the phone untouched during this test (about one minute).
The test creates one short recording; it never launches or selects an emulator.
"""
import argparse, os, shutil, subprocess, time, re
from pathlib import Path
import xml.etree.ElementTree as E
parser = argparse.ArgumentParser(description="Verify SwaraLara on a physical ADB device; creates a short microphone recording.")
parser.add_argument("--adb", default=shutil.which("adb"), help="Path to adb executable")
parser.add_argument("--serial", help="Physical device serial; defaults to the sole connected device")
args = parser.parse_args()
if not args.adb:
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    args.adb = str(Path(sdk) / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb")) if sdk else None
if not args.adb:
    parser.error("Add adb to PATH or supply --adb.")
devices = subprocess.check_output([args.adb, "devices"], text=True)
serials = [line.split()[0] for line in devices.splitlines()[1:] if len(line.split()) >= 2 and line.split()[1] == "device" and not line.startswith("emulator-")]
if not args.serial:
    if len(serials) != 1:
        parser.error("Connect one physical ADB device or supply --serial.")
    args.serial = serials[0]
if args.serial.startswith("emulator-") or args.serial not in serials:
    parser.error("A connected physical ADB device is required. Do not use an emulator.")
adb = [args.adb, "-s", args.serial]
out = Path(__file__).resolve().parents[1] / ".tools" / "frontend"
out.mkdir(parents=True, exist_ok=True)
def run(*args):
 p=subprocess.run(adb+list(args),capture_output=True,check=True)
 return p.stdout

def tree():
 focus=run('shell','dumpsys','window').decode('utf-8',errors='replace')
 line=next((x for x in focus.splitlines() if 'mCurrentFocus=' in x),'')
 assert 'id.swaralara.app/' in line, 'SwaraLara must remain in foreground'
 run('shell','uiautomator','dump','/sdcard/swaralara-ui.xml')
 return E.fromstring(run('exec-out','cat','/sdcard/swaralara-ui.xml'))
def tap(text,last=False):
 r=tree(); found=[n for n in r.iter('node') if n.get('text')==text]
 assert found, 'Missing '+text
 n=found[-1] if last else found[0]
 parents={c:p for p in r.iter() for c in p}
 while n.get('clickable')!='true' and n in parents:n=parents[n]
 assert n.get('enabled')=='true', 'Disabled '+text
 b=list(map(int,re.findall(r'\d+',n.get('bounds'))))
 run('shell','input','tap',str((b[0]+b[2])//2),str((b[1]+b[3])//2))
 time.sleep(.4)
def shot(name):
 tree()
 run('shell','screencap','-p','/sdcard/swaralara-ui.png')
 run('pull','/sdcard/swaralara-ui.png',str(out/(name+'.png')))
 print('PASS screen '+name,flush=True)
recording_started=False
try:
    run('shell','am','start','-W','-n','id.swaralara.app/.MainActivity')
    time.sleep(.5)
    # Open a fresh home by selecting the navigation item.
    tap('Beranda',True)
    for label,name in [('Brankas','brankas'),('Terpercaya','perangkat'),('Akses','akses'),('Pengaturan','pengaturan')]:
     tap(label,True);shot(name)
    tap('Beranda',True)
    r=tree();n=next(n for n in r.iter('node') if n.get('content-desc')=='Tahan untuk merekam')
    b=list(map(int,re.findall(r'\d+',n.get('bounds'))));x=str((b[0]+b[2])//2);y=str((b[1]+b[3])//2)
    run('shell','input','tap',x,y)
    r=tree();assert any(n.get('text')=='SwaraLara' for n in r.iter('node')),'Short press started recorder'
    print('PASS short press cancels',flush=True)
    recording_started=True
    run('shell','input','swipe',x,y,x,y,'1800')
    time.sleep(2)
    r=tree();assert any(n.get('text')=='Merekam' for n in r.iter('node')),'Recorder did not start'
    shot('merekam')
    tap('Berhenti merekam')
    recording_started=False
    time.sleep(1)
    shot('beranda')
    tap('Brankas',True);tap('Kejadian')
    tap('Periksa')
    r=tree();assert any(n.get('text','').replace(' ','_')=='VERIFIED_PARTIAL' for n in r.iter('node')),'Integrity did not verify'
    tap('Putar');shot('rekaman')
    tap('Putar',True)
    r=tree();assert any(re.fullmatch(r'[1-9][0-9]*/[1-9][0-9]*',n.get('text','')) for n in r.iter('node')), 'Playback position did not advance'
    tap('Tutup');tap('Beranda',True)
    print('PASS recording, integrity, prepare, play, close',flush=True)
finally:
    if recording_started:
        # Close only the test recording if an assertion/foreground check interrupted the run.
        run('shell','am','start','-W','-n','id.swaralara.app/.MainActivity')
        current=tree()
        if any(n.get('text') in {'Merekam','Menyiapkan','Menyimpan'} for n in current.iter('node')):
            tap('Berhenti merekam')
