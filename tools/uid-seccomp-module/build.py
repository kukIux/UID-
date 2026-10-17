from pathlib import Path
import argparse, hashlib, json, os, re, subprocess, zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SDK = Path(os.environ.get('ANDROID_SDK_ROOT') or os.environ.get('ANDROID_HOME') or
           str(Path(os.environ.get('LOCALAPPDATA', str(Path.home() / 'AppData/Local'))) / 'Android/Sdk'))
NDK = Path(os.environ.get('ANDROID_NDK_HOME') or str(SDK / 'ndk/27.3.13750724')) / 'toolchains/llvm/prebuilt/windows-x86_64'
HEADER = ROOT / 'third_party/zygisk/zygisk.hpp'
HEADER_SHA = 'f8d55e8b4f89d418c5941afe62ce6a09ddec1f4afd9a1b0a01eb40a93310dd28'
VERSION = '0.2.8'
VERSION_CODE = 10
DEFAULT_OUTPUT = ROOT / 'build' / VERSION

def main():
    parser = argparse.ArgumentParser(description='Build the UID Filter Zygisk module ZIP.')
    parser.add_argument('--config', type=Path)
    parser.add_argument('--module-only', action='store_true', help='Accepted for compatibility; only the module is built.')
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if not (NDK / 'bin/clang++.exe').is_file():
        parser.error('Android NDK 27.3.13750724 is required. Set ANDROID_SDK_ROOT or ANDROID_NDK_HOME.')
    build = args.output.resolve()
    (build / 'module/zygisk').mkdir(parents=True, exist_ok=True)
    assert hashlib.sha256(HEADER.read_bytes()).hexdigest() == HEADER_SHA
    env = dict(os.environ)
    def run(command):
        subprocess.run([str(x) for x in command], env=env, check=True, timeout=90)
    common = [NDK / 'bin/clang++.exe', '--target=aarch64-linux-android33', '-shared', '-fPIC',
              '-O2', '-std=c++17', '-static-libstdc++', '-Wall', '-Wextra', '-Werror',
              '-Wl,-z,max-page-size=16384', '-Wl,-z,relro,-z,now', '-fvisibility=hidden']
    library = build / 'module/zygisk/arm64-v8a.so'
    local_cxa = ROOT / 'third_party/local_cxa'
    run(common + ['-I', HEADER.parent, HERE / 'module.cpp', HERE / 'broker.cpp', local_cxa / 'atexit.cpp',
                  '-Wl,--version-script=' + str(HERE / 'exports.map'), '-Wl,--strip-all',
                  '-ldl', '-o', library])
    # Fail the build if cleanup accidentally binds to the process-wide registry.
    symbols = subprocess.run([str(NDK / 'bin/llvm-readelf.exe'), '--dyn-syms', '--wide', str(library)],
                             capture_output=True, text=True, check=True, timeout=20).stdout
    assert '__cxa_atexit' not in symbols and '__cxa_finalize' not in symbols
    assert 'zygisk_module_entry' in symbols
    assert 'zygisk_companion_entry' in symbols
    assert b'atexit' not in library.read_bytes(), 'Unexpected exit-handler symbol strings in release library'
    (build / 'module/module.prop').write_text(f'id=cq_uid_seccomp\nname=UID 过滤\nversion={VERSION}\nversionCode={VERSION_CODE}\nauthor=泷泽\ndescription=通过过滤指定包的`getpriority(PRIO_USER)`  做到规避检测\n', encoding='utf-8', newline='\n')
    (build / 'module/skip_mount').write_bytes(b'')
    for path in (HERE / 'panel').rglob('*'):
        if path.is_file():
            target = build / 'module' / path.relative_to(HERE / 'panel')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes().replace(b'\r\n', b'\n'))
    page = build / 'module/webroot/index.html'
    html, count = re.subn(r'(<span id="version">)[^<]*(</span>)',
                          lambda match: match[1] + VERSION + match[2], page.read_text(encoding='utf-8'))
    assert count == 1, 'Expected one panel version element'
    page.write_text(html, encoding='utf-8', newline='\n')
    if args.config:
        (build / 'module/defaults').write_bytes(args.config.read_bytes().replace(b'\r\n', b'\n'))
    (build / 'module/config').write_bytes((build / 'module/defaults').read_bytes())
    (build / 'module/legal').mkdir(exist_ok=True)
    for name in ('LICENSE', 'NOTICE'):
        (build / 'module/legal' / ('local-cxa-' + name)).write_bytes((local_cxa / name).read_bytes())
    module_files = sorted(p for p in (build / 'module').rglob('*')
                          if p.is_file() and p.name != 'SHA256SUMS')
    (build / 'module/SHA256SUMS').write_text(''.join(
        hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.relative_to(build / 'module').as_posix() + '\n'
        for path in module_files), encoding='ascii', newline='\n')
    with zipfile.ZipFile(build / f'cq-uid-seccomp-{VERSION}.zip', 'w', zipfile.ZIP_DEFLATED) as z:
        for path in sorted((build / 'module').rglob('*')):
            if path.is_file(): z.write(path, path.relative_to(build / 'module').as_posix())
    module_artifacts = [build / f'cq-uid-seccomp-{VERSION}.zip', build / 'module/zygisk/arm64-v8a.so']
    package = module_artifacts[0]
    package.with_suffix('.zip.sha256').write_text(
        hashlib.sha256(package.read_bytes()).hexdigest() + '  ' + package.name + '\n',
        encoding='ascii', newline='\n')
    artifacts = {path.name: {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size}
                 for path in module_artifacts}
    (build / 'artifacts.json').write_text(json.dumps(artifacts, indent=2), encoding='utf-8')
    print(json.dumps(artifacts, indent=2))

if __name__ == '__main__': main()
