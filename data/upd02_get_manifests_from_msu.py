from pathlib import Path
import subprocess
import hashlib
import shutil
import sys

from delta_patch import unpack_null_differential_file
import config

# https://stackoverflow.com/a/44873382
def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()


def extract_update_file(local_dir: Path, msuFile: Path):
    def cab_extract(pattern: str, from_file: Path, to_dir: Path):
        to_dir.mkdir(parents=True, exist_ok=True)
        print(to_dir)
        args = ['expand', f'-f:{pattern}', from_file, to_dir]
        subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)

    # Extract all files from all cab files until no more cab files can be found.
    first_unhandled_extract_dir_num = 1
    next_extract_dir_num = 1

    extract_dir = local_dir.joinpath(f'_extract_{next_extract_dir_num}')
    next_extract_dir_num += 1
    cab_extract('*', msuFile, extract_dir)
    # msuFile.unlink()

    while first_unhandled_extract_dir_num < next_extract_dir_num:
        next_unhandled_extract_dir_num = next_extract_dir_num

        for src_extract_dir_num in range(first_unhandled_extract_dir_num, next_extract_dir_num):
            src_extract_dir = local_dir.joinpath(f'_extract_{src_extract_dir_num}')
            for cab in src_extract_dir.glob('*.cab'):
                extract_dir = local_dir.joinpath(f'_extract_{next_extract_dir_num}')
                next_extract_dir_num += 1
                cab_extract('*', cab, extract_dir)
                cab.unlink()

        first_unhandled_extract_dir_num = next_unhandled_extract_dir_num

    # Move all extracted files from all folders to the target folder.
    for extract_dir in local_dir.glob('_extract_*'):
        def ignore_files(path, names):
            source_dir = Path(path)
            destination_dir = local_dir.joinpath(Path(path).relative_to(extract_dir))

            ignore = []
            for name in names:
                source_file = source_dir.joinpath(name)
                if source_file.is_file():
                    # Ignore files in root folder which have different non-identical copies with the same name.
                    # Also ignore cab archives in the root folder.
                    if source_dir == extract_dir:
                        if (name in ['update.cat', 'update.mum'] or
                            name.endswith('.cab') or
                            name.endswith('.dll')):
                           ignore.append(name)
                           continue

                    # Ignore files which already exist as long as they're identical.
                    destination_file = destination_dir.joinpath(name)
                    if destination_file.exists():
                        if not destination_file.is_file():
                            raise Exception(f'A destination item already exists and is not a file: {destination_file}')

                        if sha256sum(source_file) != sha256sum(destination_file):
                            raise Exception(f'A different file copy already exists: {destination_file}')

                        ignore.append(name)

            return ignore

        shutil.copytree(extract_dir, local_dir, copy_function=shutil.move, dirs_exist_ok=True, ignore=ignore_files)
        shutil.rmtree(extract_dir)

    # Extract delta files from the PSF file which can be found in Windows 11 updates.
    # References:
    # https://www.betaarchive.com/forum/viewtopic.php?t=43163
    # https://github.com/Secant1006/PSFExtractor
    psf_files = list(local_dir.glob('*.psf'))
    assert len(psf_files) <= 1
    if len(psf_files) == 1:
        psf_file = psf_files[0]
        args = ['tools/PSFExtractor.exe', '-v2', psf_file, local_dir.joinpath('express.psf.cix.xml'), local_dir]
        subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)
        psf_file.unlink()

    # Make sure there are no MSU files.
    # msu_files = list(local_dir.glob('*.msu'))
    # assert len(msu_files) == 0

    # Unpack null differential files.
    for file in local_dir.glob('*/n/**/*'):
        if file.is_file():
            unpack_null_differential_file(file, file)

    local_dir_resolved = local_dir.resolve(strict=True)
    local_dir_unc = Rf'\\?\{local_dir_resolved}'

    # Use DeltaDownloader to extract meaningful data from delta files:
    # https://github.com/m417z/DeltaDownloader
    # Avoid path length limitations by using a UNC path.
    args = ['tools/DeltaDownloader/DeltaDownloader.exe', '/g', local_dir_unc]
    subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)

    # Starting with Windows 11, manifest files are compressed with the DCM v1 format.
    # Use SYSEXP to de-compress them: https://github.com/hfiref0x/SXSEXP
    # Avoid some path length limitations by using a resolved path (the limit is
    # still MAX_PATH).
    args = ['tools/sxsexp64.exe', local_dir_resolved, local_dir_resolved]
    subprocess.run(args, stdout=None if config.verbose_run else subprocess.DEVNULL)




def download_update(windows_version, update_kb):
    update_uid, update_title = get_update(windows_version, update_kb)
    download_url = get_update_download_url(update_uid)
    if not download_url:
        raise Exception('Update not found in catalog')

    local_dir = config.out_path.joinpath('manifests', windows_version, update_kb)
    local_dir.mkdir(parents=True, exist_ok=True)

    local_filename = download_url.split('/')[-1]
    local_path = local_dir.joinpath(local_filename)

    #with requests.get(download_url, stream=True) as r:
    #    with open(local_path, 'wb') as f:
    #        shutil.copyfileobj(r.raw, f)

    args = ['aria2c', '-x4', '-o', local_path, '--allow-overwrite=true', download_url]
    subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)

    return download_url, local_dir, local_path

def main(files : list):
    for file in files:
        buildNum = file.split('-')[1].split('-')[0]
        manifests = Path('manifests', buildNum)
        manifests.mkdir(parents=True, exist_ok=True)
        extract_update_file(manifests, Path(file))


if __name__ == '__main__':
    files = [sys.argv[1], sys.argv[2]]
    main(files)
