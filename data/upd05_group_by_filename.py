from isal import igzip as gzip
from datetime import datetime
from pathlib import Path
import glob
import bisect
import orjson
import json
import re

import config

file_info_data = {}
diff_data = {}


def write_to_gzip_file(file, data):
    with open(file, 'wb') as fd:
        with gzip.GzipFile(fileobj=fd, mode='w', compresslevel=config.compression_level, filename='', mtime=0) as gz:
            gz.write(data)


def write_all_file_info():
    output_dir = config.out_path.joinpath('by_filename_compressed')

    for filename in file_info_data:
        data = file_info_data[filename]

        output_path = output_dir.joinpath(filename + '.json.gz')
        write_to_gzip_file(output_path, orjson.dumps(data))

    file_info_data.clear()

    all_filenames = sorted(path.with_suffix('').stem for path in output_dir.glob('*.json.gz'))

    with open(config.out_path.joinpath('filenames.json'), 'w') as f:
        json.dump(all_filenames, f, indent=0, sort_keys=True)


def get_file_info_type(file_info):
    if 'machineType' not in file_info:
        if file_info.keys() == {
            'size',
            'md5',
        }:
            return 'raw'

        if file_info.keys() == {
            'size',
            'md5',
            'sha1',
            'sha256',
        }:
            return 'raw_file'

        assert False, file_info

    if file_info.keys() == {
        'size',
        'md5',
        'machineType',
        'timestamp',
        'lastSectionVirtualAddress',
        'lastSectionPointerToRawData',
    }:
        return 'delta'

    if file_info.keys() == {
        'size',
        'md5',
        'machineType',
        'timestamp',
        'lastSectionVirtualAddress',
        'lastSectionPointerToRawData',
        'virtualSize',
    }:
        return 'delta+'

    assert 'lastSectionVirtualAddress' not in file_info
    assert 'lastSectionPointerToRawData' not in file_info

    # For old info.
    if file_info.keys() == {
        'size',
        'md5',
        'machineType',
        'timestamp',
        'virtualSize',
    }:
        return 'pe'
    
    assert file_info.keys() >= {
        'size',
        'md5',
        'sha1',
        'sha256',
        'machineType',
        'timestamp',
        'virtualSize',
        'signingStatus',
    }, file_info

    if file_info['signingStatus'] == 'Unknown':
        return 'file_unknown_sig'

    return 'vt_or_file'


def assert_file_info_close_enough(file_info_1, file_info_2):
    def canonical_file_info(file_info):
        file_info = file_info.copy()

        # VirusTotal strips whitespaces in descriptions.
        if 'description' in file_info:
            file_info['description'] = file_info['description'].strip()
            if file_info['description'].strip() == '':
                del file_info['description']

        # VirusTotal strips whitespaces in versions.
        if 'version' in file_info:
            file_info['version'] = file_info['version'].strip()
            if file_info['version'].strip() == '':
                del file_info['version']

        # Nullify Catalog file based data since it depends on the computer the scan ran on.
        if file_info.get('signatureType') == 'Catalog file':
            assert 'signingDate' not in file_info
            file_info['signingStatus'] = 'Unsigned'
            del file_info['signatureType']

        return file_info

    # Must be equal for all information sources.
    assert file_info_1['size'] == file_info_2['size']

    # Non-PE file.
    if 'machineType' not in file_info_1:
        non_pe_keys = {
            'md5',
            'sha1',
            'sha256',
            'size',
        }
        assert file_info_1.keys() <= non_pe_keys
        assert file_info_2.keys() <= non_pe_keys
        for key in file_info_1.keys() & file_info_2.keys():
            assert file_info_1[key] == file_info_2[key]
        return

    # Must be equal for all information sources.
    assert file_info_1['machineType'] == file_info_2['machineType']
    assert file_info_1['timestamp'] == file_info_2['timestamp']

    delta_or_pe_types = ['delta', 'delta+', 'pe']
    if get_file_info_type(file_info_1) in delta_or_pe_types or get_file_info_type(file_info_2) in delta_or_pe_types:
        for key in file_info_1.keys() & file_info_2.keys():
            assert file_info_1[key] == file_info_2[key]
        return

    file_info_1 = canonical_file_info(file_info_1)
    file_info_2 = canonical_file_info(file_info_2)

    assert file_info_1.keys() - {'signingDate'} == file_info_2.keys() - {'signingDate'}, (file_info_1, file_info_2)

    for key in file_info_1.keys() - {'signingStatus', 'signingDate'}:
        assert file_info_1[key] == file_info_2[key], (file_info_1, file_info_2)

    if 'signingStatus' in file_info_1:
        if file_info_1['signingStatus'] == 'Unknown':
            assert file_info_2['signingStatus'] != 'Unsigned'
        elif file_info_2['signingStatus'] == 'Unknown':
            assert file_info_1['signingStatus'] != 'Unsigned'
        else:
            assert file_info_1['signingStatus'] == file_info_2['signingStatus']

    if 'signingDate' in file_info_1 and 'signingDate' in file_info_2:
        if file_info_1['signingDate'] != [] and file_info_2['signingDate'] != []:
            # Compare only first date.
            datetime1 = datetime.fromisoformat(file_info_1['signingDate'][0])
            datetime2 = datetime.fromisoformat(file_info_2['signingDate'][0])
            difference = datetime1 - datetime2
            hours = abs(difference.total_seconds()) / 3600

            # VirusTotal returns the time in a local, unknown timezone.
            # "the maximum difference could be over 30 hours", https://stackoverflow.com/a/8131056
            assert hours <= 32, f'{hours} {file_info_1["sha256"]}'
        else:
            assert file_info_1['signingDate'] == []
            assert file_info_2['signingDate'] == []
    else:
        # If the signature is invalid (but exists), VirusTotal doesn't return dates, but we do.
        if 'signingDate' not in file_info_1:
            assert file_info_1['signingStatus'] != 'Signed'

        if 'signingDate' not in file_info_2:
            assert file_info_2['signingStatus'] != 'Signed'


def update_file_info(existing_file_info, new_file_info, new_file_info_source):
    if existing_file_info is None:
        return new_file_info

    if new_file_info is None:
        return existing_file_info

    assert_file_info_close_enough(existing_file_info, new_file_info)

    if new_file_info_source == 'iso':
        new_file_info_type = 'file'
    elif new_file_info_source == 'vt':
        new_file_info_type = 'vt'
    elif new_file_info_source == 'update':
        new_file_info_type = get_file_info_type(new_file_info)
        if new_file_info_type == 'vt_or_file':
            new_file_info_type = 'file'
    else:
        assert False

    existing_file_info_type = get_file_info_type(existing_file_info)

    sources = [
        'raw',
        'raw_file',
        'delta',
        'delta+',
        'pe',
        # 'file_unknown_sig',
        'vt',
        'vt_or_file',
        'file',
    ]

    # Special merge: file_unknown_sig data is more reliable than VirusTotal's. Only add signingStatus.
    if existing_file_info_type == 'file_unknown_sig':
        if 'signingStatus' in new_file_info:
            assert new_file_info['signingStatus'] != 'Unsigned'
            return existing_file_info | {'signingStatus': new_file_info['signingStatus']}
        return existing_file_info
    elif new_file_info_type == 'file_unknown_sig':
        if 'signingStatus' in existing_file_info:
            assert existing_file_info['signingStatus'] != 'Unsigned'
            return new_file_info | {'signingStatus': existing_file_info['signingStatus']}
        return new_file_info

    if sources.index(new_file_info_type) > sources.index(existing_file_info_type):
        return new_file_info

    return existing_file_info


def add_file_info_from_update(filename, output_dir, *,
                              file_hash,
                              virustotal_file_info,
                              windows_version,
                              update_kb,
                              update_info,
                              manifest_name,
                              assembly_identity,
                              attributes,
                              delta_or_pe_file_info):
    data = None
    data_file = None
    json_data_file_before = None
    json_data_file_after = None

    if filename in file_info_data:
        data = file_info_data[filename]
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        if output_path.is_file():
            with gzip.open(output_path, 'rb') as f:
                json_data = f.read()

            # Try an optimization - operate only on the relevant part of the json.
            match = None
            if not config.high_mem_usage_for_performance:
                match = re.search(rb'"' + file_hash.encode() + rb'":({.*?})(?:,"[0-9a-f]{64}":{|}$)', json_data)

            if match:
                data_file = orjson.loads(match.group(1))
                json_data_file_before = json_data[:match.start(1)]
                json_data_file_after = json_data[match.end(1):]
            else:
                data = orjson.loads(json_data)
        else:
            data = {}

    if data_file is not None:
        assert data is None
        x = data_file
    else:
        assert data is not None
        x = data.setdefault(file_hash, {})

    updated_file_info = update_file_info(x.get('fileInfo'), delta_or_pe_file_info, 'update')
    updated_file_info = update_file_info(updated_file_info, virustotal_file_info, 'vt')
    if updated_file_info:
        x['fileInfo'] = updated_file_info

    x = x.setdefault('windowsVersions', {})
    x = x.setdefault(windows_version, {})
    x = x.setdefault(update_kb, {})

    if 'updateInfo' not in x:
        x['updateInfo'] = update_info
    else:
        assert x['updateInfo'] == update_info

    x = x.setdefault('assemblies', {})
    x = x.setdefault(manifest_name, {})

    if 'assemblyIdentity' not in x:
        x['assemblyIdentity'] = assembly_identity
    else:
        assert x['assemblyIdentity'] == assembly_identity

    x = x.setdefault('attributes', [])

    if attributes not in x:
        x.append(attributes)

    if config.high_mem_usage_for_performance:
        assert data is not None
        file_info_data[filename] = data
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')

        if data_file is not None:
            assert isinstance(json_data_file_before, bytes)
            assert isinstance(json_data_file_after, bytes)
            json_data = json_data_file_before + orjson.dumps(data_file) + json_data_file_after
        else:
            json_data = orjson.dumps(data)

        write_to_gzip_file(output_path, json_data)

    if updated_file_info and updated_file_info.get("timestamp") and updated_file_info.get("virtualSize"):
        y = diff_data[filename] # return dict
        y = y[file_hash] # return dict

        timestamp = updated_file_info["timestamp"]
        virtualSize = updated_file_info["virtualSize"]
        y["link"] = f"https://msdl.microsoft.com/download/symbols/{filename}/{timestamp:08x}{virtualSize:x}/{filename}"


virustotal_info_cache = {}


def get_virustotal_info(file_hash):
    # https://stackoverflow.com/a/57027610
    def is_power_of_two(n):
        return (n != 0) and (n & (n-1) == 0)

    def align_by(n, alignment):
        return ((n + alignment - 1) // alignment) * alignment

    if config.high_mem_usage_for_performance and file_hash in virustotal_info_cache:
        return virustotal_info_cache[file_hash]

    if len(file_hash) == 64:
        # SHA256, the default.
        source_dir = 'virustotal'
    elif len(file_hash) == 40:
        source_dir = 'virustotal_sha1'
    else:
        assert False, file_hash

    filename = config.out_path.joinpath(source_dir, file_hash + '.json')
    if not filename.is_file():
        if config.high_mem_usage_for_performance:
            virustotal_info_cache[file_hash] = None
        return None

    with open(filename) as f:
        data = json.load(f)

    attr = data['data']['attributes']

    first_section = attr['pe_info']['sections'][0]

    # Handle special cases.
    if attr.get('signature_info', {}).get('description') in config.tcb_launcher_descriptions:
        assert first_section['virtual_address'] in config.tcb_launcher_large_first_section_virtual_addresses, file_hash
        section_alignment = 0x1000
    elif unusual_section_alignment_info := config.file_hashes_unusual_section_alignment.get(file_hash):
        assert first_section['virtual_address'] == unusual_section_alignment_info['first_section_virtual_address']
        section_alignment = unusual_section_alignment_info['section_alignment']
    else:
        section_alignment = first_section['virtual_address']
        assert is_power_of_two(section_alignment), file_hash

    virtual_size = first_section['virtual_address']
    for section in attr['pe_info']['sections']:
        assert virtual_size == section['virtual_address'], file_hash
        virtual_size += align_by(section['virtual_size'], section_alignment)

    if 'timestamp' in attr['pe_info']:
        timestamp = attr['pe_info']['timestamp']
    else:
        assert file_hash in config.file_hashes_zero_timestamp, file_hash
        timestamp = 0

    info = {
        'size': attr['size'],
        'md5': attr['md5'],
        'sha1': attr['sha1'],
        'sha256': attr['sha256'],
        'machineType': attr['pe_info']['machine_type'],
        'timestamp': timestamp,
        'virtualSize': virtual_size,
    }

    has_signature_overlay = False
    if 'overlay' in attr['pe_info']:
        overlay_size = attr['pe_info']['overlay']['size']
        if overlay_size < 0x20:
            assert file_hash in config.file_hashes_small_non_signature_overlay, file_hash
        elif file_hash in config.file_hashes_unsigned_with_overlay:
            pass
        elif any(attr.get('signature_info', {}).get(x['k']) == x['v'] and overlay_size == x['overlay_size']
                 for x in config.file_details_unsigned_with_overlay):
            pass
        else:
            has_signature_overlay = True

    info['signingStatus'] = 'Unsigned'
    file_signed = False

    if 'signature_info' in attr:
        signature_info = attr['signature_info']

        if 'file version' in signature_info:
            info['version'] = signature_info['file version']

        if 'description' in signature_info:
            info['description'] = signature_info['description']

        signing_date_reliable = False
        if 'verified' in signature_info:
            info['signingStatus'] = signature_info['verified']
            info['signatureType'] = 'Overlay' if has_signature_overlay else 'Catalog file'
            file_signed = True

            # If the value is something else, the "signing date" is often the analysis date.
            if signature_info['verified'] == 'Signed':
                signing_date_reliable = True

        if has_signature_overlay and 'signing date' in signature_info and signing_date_reliable:
            spaces = signature_info['signing date'].count(' ')
            if spaces == 1:
                # Examples:
                # 9:51 09/05/2020
                # 13:18 21/02/2020
                date_format = '%H:%M %d/%m/%Y'
            else:
                assert spaces == 2, file_hash
                # Examples:
                # 8:30 AM 2/7/2020
                # 5:47 PM 9/19/2019
                date_format = '%I:%M %p %m/%d/%Y'

            datetime_object = datetime.strptime(signature_info['signing date'], date_format)
            info['signingDate'] = [datetime_object.isoformat()]

            # If this assertion fails, the "signing date" might be the analysis
            # date, in which case the signature type is "Catalog file", and
            # has_signature_overlay should be False.
            assert datetime_object.timestamp() < attr['first_submission_date'], file_hash

    assert not has_signature_overlay or file_signed, file_hash

    if config.high_mem_usage_for_performance:
        virustotal_info_cache[file_hash] = info
    else:
        virustotal_info_cache[file_hash] = True

    return info


def group_update_assembly_by_filename(input_filename, output_dir, *, windows_version, update_kb, update_info, manifest_name):
    with open(input_filename) as f:
        data = json.load(f)

    assembly_identity = data['assemblyIdentity']

    for file_item in data['files']:
        filename = file_item['attributes']['name'].split('\\')[-1].lower()

        hash_is_sha256 = 'sha256' in file_item
        if hash_is_sha256:
            file_hash = file_item['sha256']
        else:
            file_hash = file_item['sha1']

        virustotal_info = get_virustotal_info(file_hash)
        if virustotal_info and file_hash != virustotal_info['sha256']:
            assert file_hash == virustotal_info['sha1']
            file_hash = virustotal_info['sha256']
            hash_is_sha256 = True

        if not hash_is_sha256:
            if config.allow_missing_sha256_hash:
                print(f'WARNING: No SHA256 hash for {filename} ({file_hash}) in {input_filename}')
                continue
            raise Exception('No SHA256 hash')

        # Skip files with what seems to be a hash mismatch.
        file_hash_md5 = file_item.get('fileInfo', {}).get('md5')
        if (file_hash, file_hash_md5) in config.file_hashes_mismatch:
            assert windows_version in config.file_hashes_mismatch[(file_hash, file_hash_md5)]
            print(f'WARNING: Skipping file with (probably) an incorrect SHA256 hash: {file_hash}')
            print(f'         MD5 hash: {file_hash_md5}')
            print(f'         Manifest name: {manifest_name}')
            continue

        add_file_info_from_update(filename, output_dir,
            file_hash=file_hash,
            virustotal_file_info=virustotal_info,
            windows_version=windows_version,
            update_kb=update_kb,
            update_info=update_info,
            manifest_name=manifest_name,
            assembly_identity=assembly_identity,
            attributes=file_item['attributes'],
            delta_or_pe_file_info=file_item.get('fileInfo'))


def group_update_by_filename(windows_version, update_kb, update, parsed_dir, progress_state=None, time_to_stop=None):
    output_dir = config.out_path.joinpath('by_filename_compressed')
    output_dir.mkdir(parents=True, exist_ok=True)

    paths = sorted(parsed_dir.glob('*.json'))  # for reproducible order
    count_total = len(paths)

    if progress_state:
        assert progress_state['update_kb'] == update_kb

        count = progress_state['files_processed']

        if progress_state['files_total'] is None:
            progress_state['files_total'] = count_total
        else:
            assert progress_state['files_total'] == count_total

        paths = paths[count:]
    else:
        count = 0

    for path in paths:
        if time_to_stop and datetime.now() >= time_to_stop:
            break

        if path.is_file():
            try:
                group_update_assembly_by_filename(path, output_dir,
                    windows_version=windows_version,
                    update_kb=update_kb,
                    update_info=update,
                    manifest_name=path.stem)
            except Exception as e:
                print(f'ERROR: failed to process {path}')
                print(f'       {e}')
                if config.exit_on_first_error:
                    raise

        count += 1
        if count % 200 == 0 and config.verbose_progress:
            print(f'Processed {count} of {count_total}')

    if progress_state:
        progress_state['files_processed'] = count


def add_file_info_from_virustotal_data(filename, output_dir, *, file_hash, file_info):
    if filename in file_info_data:
        data = file_info_data[filename]
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        if output_path.is_file():
            with gzip.open(output_path, 'rb') as f:
                data = orjson.loads(f.read())
        else:
            data = {}

    x = data[file_hash]

    updated_file_info = update_file_info(x.get('fileInfo'), file_info, 'vt')
    assert updated_file_info
    x['fileInfo'] = updated_file_info

    if config.high_mem_usage_for_performance:
        file_info_data[filename] = data
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        write_to_gzip_file(output_path, orjson.dumps(data))


def process_virustotal_data():
    global diff_data

    info_progress_virustotal_path = config.out_path.joinpath('info_progress_virustotal.json')
    if info_progress_virustotal_path.is_file():
        with open(info_progress_virustotal_path, 'r') as f:
            info_progress_virustotal = json.load(f)
    else:
        info_progress_virustotal = {}

    pending = info_progress_virustotal.get('pending', {})

    for name in pending:
        for file_hash in pending[name]:
            if file_hash in virustotal_info_cache:
                # Was already added with one of the updates.
                continue

            virustotal_info = get_virustotal_info(file_hash)
            assert virustotal_info is not None
            if file_hash != virustotal_info['sha256']:
                assert file_hash == virustotal_info['sha1']
                file_hash = virustotal_info['sha256']

            if virustotal_info and virustotal_info.get("timestamp") and virustotal_info.get("virtualSize"):
                timestamp = virustotal_info["timestamp"]
                virtualSize = virustotal_info["virtualSize"]
                diff_data[name][file_hash]["link"] = f"https://msdl.microsoft.com/download/symbols/{name}/{timestamp:08x}{virtualSize:x}/{name}"

    info_progress_virustotal['pending'] = {}

    with open(info_progress_virustotal_path, 'w') as f:
        json.dump(info_progress_virustotal, f, indent=0, sort_keys=True)

    virustotal_info_cache.clear()

def main(progress_state=None, time_to_stop=None):
    global diff_data

    with open("info_sources_mk2.json", "r") as f:
        diff_data = json.load(f)

    print('Processing data from VirusTotal')
    process_virustotal_data()

    for v in diff_data.values():
        for vv in v.values():
            del vv["file_type"]

    with open("diff_data.json", "w") as f:
        json.dump(diff_data, f, indent=2)


if __name__ == '__main__':
    main()
