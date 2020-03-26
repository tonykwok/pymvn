# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import hashlib
import logging
import os.path
import sys
import xml.etree.ElementTree as ET

try:
    # Python 3
    from urllib.request import Request, urlopen
except ImportError:
    # Python 2
    from urllib2 import Request, urlopen

from .configuration import get_repository, get_stagedir, get_repository_shortname
from common.config import AUTHORIZATION, URL, load_config


def download_artifact(name, repo_name, download_deps=False):
    """
    Downloads a single artifact.

    :param name: name of the artifact to download, following the group_id:artifact_id:version format
    :param repo_name: name of the repository to look for artifacts
    :param download_deps: True if the dependencies must be downloaded
    """
    logging.info("downloading %s", name)

    config = load_config()
    repository = get_repository(config, repo_name)
    stage_dir = get_stagedir(config)

    _download_single_artifact(name, repository, stage_dir, download_deps)


def download_bulk(filename, repo_name, download_deps=False):
    """
    Downloads artifacts from a file, one artifact per line.

    :param filename: name of the file containing the artifacts to download
    :param repo_name: name of the repository to look for artifacts
    :param download_deps: True if the dependencies must be downloaded
    """
    logging.info("downloading from file %s", filename)

    config = load_config()
    repository = get_repository(config, repo_name)
    stage_dir = get_stagedir(config)

    with open(filename, "r") as file:
        lines = file.readlines()
        for line in lines:
            line = line.strip().rstrip()
            if line:
                _download_single_artifact(
                    line, repository, stage_dir, download_deps
                )


def _download_single_artifact(name, repository, stage_dir, download_deps):
    logging.debug("download url: %s", repository[URL])
    logging.debug("stage directory: %s", stage_dir)

    if not os.path.exists(stage_dir):
        raise ValueError("Output directory doesn't exist: " + stage_dir)

    values = name.split(":")
    if len(values) == 3:
        group_id = values[0]
        artifact_name = values[1]
        # try to guess if we have a bom file
        if "-bom" in artifact_name:
            artifact_type = "pom"
        else:
            artifact_type = "jar"
        version = values[2]
        artifact_fullname = artifact_name + "-" + version
    elif len(values) == 4:
        group_id = values[0]
        artifact_name = values[1]
        artifact_type = values[2]
        version = values[3]
        artifact_fullname = artifact_name + "-" + version
    elif len(values) == 5:
        group_id = values[0]
        artifact_name = values[1]
        artifact_type = values[2]
        version = values[4]
        artifact_fullname = artifact_name + "-" + version + "-" + values[3]
    else:
        logging.warning("Artifact doesn't have correct format. Skipping " + name)
        return

    artifact_path = group_id.replace(".", "/") + "/" + artifact_name + "/" + version

    if artifact_type in ["aar", "jar", "war"]:
        files2download = _java_artifacts(
            artifact_fullname, artifact_type, artifact_path, download_deps
        )
    else:
        files2download = _untyped_artifacts(
            artifact_fullname, artifact_type, artifact_path, download_deps
        )

    for file2download in files2download:
        # let's always download POM files in case we need to process the parent POM
        # once again or upload the children dependencies.
        outfile = os.path.join(stage_dir, file2download["path"], file2download["name"])
        os.makedirs(os.path.dirname(outfile), exist_ok=True)
        print("Local artifact: %s" % outfile)

        artifact_relativepath = file2download["path"] + "/" + file2download["name"]
        _download_file(repository, artifact_relativepath, outfile)
        if not os.path.exists(outfile):
            logging.info("%s was not downloaded. Skipping", outfile)
            if file2download["target"]:
                logging.warning(
                    "%s was not found in the repository", file2download["name"]
                )
            continue

        if file2download["name"].endswith(".pom"):
            # a library will not be installed if its parent pom.xml file
            # is not present in the repository, so let's download the
            # parent POM file but without downloading its dependencies.
            tree = ET.parse(outfile)
            parent_node = tree.getroot().find(
                "{http://maven.apache.org/POM/4.0.0}parent"
            )
            if parent_node is not None:
                parent_group_id = _find_node_value(parent_node, "groupId")
                parent_artifact_id = _find_node_value(parent_node, "artifactId")
                parent_version = _find_node_value(parent_node, "version")
                parent_path = (
                    parent_group_id.replace(".", "/")
                    + "/"
                    + parent_artifact_id
                    + "/"
                    + parent_version
                )

                files2download.append(
                    _pom_artifact(
                        parent_artifact_id + "-" + parent_version, parent_path
                    )
                )

            if (
                "download_deps" not in file2download
                or not file2download["download_deps"]
            ):
                logging.info(
                    "skip downloading dependencies from %s", file2download["name"]
                )
                continue

            # try to download the dependencies
            dependencies_node = tree.getroot().find(
                "{http://maven.apache.org/POM/4.0.0}dependencies"
            )
            if dependencies_node is None:
                continue

            logging.debug("Downloading children")
            for dependency_node in dependencies_node.getchildren():
                dep_group_id = _find_node_value(dependency_node, "groupId")
                dep_artifact_id = _find_node_value(dependency_node, "artifactId")
                dep_artifact_type = _find_node_value(dependency_node, "packaging")
                dep_version = _find_node_value(dependency_node, "version")

                # we're only downloading `compile` versions. The user can
                # easily download other dependencies if needed.
                dep_scope = _find_node_value(dependency_node, "scope")
                if dep_scope is not None and dep_scope != "compile":
                    logging.info(
                        "skip downloading %s:%s with scope %s",
                        dep_group_id,
                        dep_artifact_id,
                        dep_scope,
                    )
                    continue

                # if no version has been defined, than it's getting potentially
                # tricky so let's just give up and let the user deal with it
                if dep_version is None:
                    logging.error(
                        "missing explicit version for %s:%s in %s. Skipping",
                        dep_group_id,
                        dep_artifact_id,
                        file2download["name"],
                    )
                    continue

                # defaults packaging type to jar if unspecified
                if dep_artifact_type is None:
                    dep_artifact_type = "jar"

                # let's download the dependency
                artifact_fullname = dep_artifact_id + "-" + dep_version
                artifact_path = (
                    dep_group_id.replace(".", "/")
                    + "/"
                    + dep_artifact_id
                    + "/"
                    + dep_version
                )
                files2download.extend(
                    _java_artifacts(
                        artifact_fullname,
                        dep_artifact_type,
                        artifact_path,
                        download_deps,
                    )
                )


# Definitions of the artifacts to download:
#  - name: name of the artifact
#  - path: full path of the artifact, will be prepended to the urls
#  - download_deps: true if the dependencies defined in the pom file must be downloaded
#  - target: true if definition was created for an artifact that was
#            explicitly requested. Used for logging purpose.


def _pom_artifact(artifact_fullname, artifact_path):
    return {
        "name": artifact_fullname + ".pom",
        "path": artifact_path,
        "download_deps": False,
        "target": False,
    }


def _java_artifacts(artifact_fullname, artifact_type, artifact_path, download_deps):
    return [
        {
            "name": artifact_fullname + "." + artifact_type,
            "path": artifact_path,
            "target": True,
        },
        {
            "name": artifact_fullname + ".pom",
            "path": artifact_path,
            "download_deps": download_deps,
            "target": False,
        },
        {
            "name": artifact_fullname + "-tests.jar",
            "path": artifact_path,
            "target": False,
        },
        {
            "name": artifact_fullname + "-sources.jar",
            "path": artifact_path,
            "target": False,
        },
        {
            "name": artifact_fullname + "-javadoc.jar",
            "path": artifact_path,
            "target": False,
        },
    ]


def _untyped_artifacts(artifact_fullname, artifact_type, artifact_path, download_deps):
    return [
        {
            "name": artifact_fullname + "." + artifact_type,
            "path": artifact_path,
            "download_deps": download_deps,
            "target": True,
        },
        {
            "name": artifact_fullname + ".pom",
            "path": artifact_path,
            "download_deps": download_deps,
            "target": False,
        },
    ]


def _find_node_value(node, name):
    found_node = node.find("{http://maven.apache.org/POM/4.0.0}" + name)
    if found_node is None:
        return None
    return found_node.text


def _download_file(repository, path, filename, length=16 * 1024, ):
    """
    Stores the path into the given filename.
    """
    if URL not in repository or not repository[URL]:
        raise ValueError(
            "Repository missing url: " + get_repository_shortname(repository)
        )

    url = _append_url(repository[URL], path)
    logging.debug("downloading from %s", url)

    print("remote md5 file url: " + url + ".md5")
    if verify_md5(filename, repository, remote_md5=url + ".md5"):
        logging.debug("%s already up-to-date", filename)
        return

    try:
        request = _create_request(repository, url)
        response = urlopen(request)
        with open(filename, "wb") as file:
            # shutil.copyfileobj(response, file, length)
            _write_chunks(response, file, report_hook=_chunk_report)
    except Exception as ex:
        logging.debug("exception while downloading (expected): %s", ex)


def _append_url(base_url, fragment):
    return base_url + fragment if base_url.endswith("/") else base_url + "/" + fragment


def _create_request(repository, url):
    headers = {"User-Agent": "Maven Artifact Downloader/1.0"}
    if AUTHORIZATION in repository and repository[AUTHORIZATION]:
        logging.debug("authorization header added")
        headers["Authorization"] = repository[AUTHORIZATION]
    else:
        logging.debug("no authorization configured")

    return Request(url, None, headers)


def _chunk_report(bytes_so_far, chunk_size, total_size):
    percent = float(bytes_so_far) / total_size
    percent = round(percent * 100, 2)
    sys.stdout.write("Downloaded %d of %d bytes (%0.2f%%)\r" % (bytes_so_far, total_size, percent))

    if bytes_so_far >= total_size:
        sys.stdout.write('\n')


def _write_chunks(response, file, chunk_size=8192, report_hook=None):
    total_size = response.info().get('Content-Length').strip()
    total_size = int(total_size)
    bytes_so_far = 0

    while 1:
        chunk = response.read(chunk_size)
        bytes_so_far += len(chunk)

        if not chunk:
            break

        file.write(chunk)
        if report_hook:
            report_hook(bytes_so_far, chunk_size, total_size)

    return bytes_so_far


def verify_md5(file, repository, remote_md5):
    if not os.path.exists(file):
        return False
    else:
        local_md5 = _local_md5(file)
        remote = None
        try:
            request = _create_request(repository, remote_md5)
            response = urlopen(request)
            remote = response.read().decode()
        except Exception as ex:
            logging.debug("exception while downloading (expected): %s", ex)

        sys.stdout.write("md5: %s v.s. %s\n" % (local_md5, remote))
        return local_md5 == remote


def _local_md5(file):
    md5 = hashlib.md5()
    with open(file, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
    return md5.hexdigest()