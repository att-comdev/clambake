#!/usr/bin/env python
import subprocess
import extractnested
import os
import sys
import datetime
import yaml
import git
import shutil
import tempfile
import pdb
import re
import errno

class Scanner():
    def __init__(self):
        """Initialize the Scanner."""

        clam_version = subprocess.check_output(['clamscan',
            '--version'])
        self.clamav_version = re.split('[\s\/]', clam_version)[1]

        proc = subprocess.Popen(['sigtool', '--info=/var/lib/clamav/main.cvd'],
            stdout=subprocess.PIPE)
        self.clamav_definitions = subprocess.Popen(['grep', '^Version'],
            stdin=proc.stdout, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE).communicate()[0].split()[1]
        proc.stdout.close()

        self.layerList = {}
        self.scannedLayers = []
        self.yaml_report = {
            'clamAV_version': self.clamav_version,
            'clamAV_definitions': self.clamav_definitions,
            'beginTime': datetime.datetime.utcnow(),
            'images': []
        }

    def getEnvironmentVariables(self):
        """Populate variables from Linux environment variables.

        Required Variables:
        dockerServer (docker server for docker login ex: docker-server.domain.com)
        gerritUsername (username used to access code base)
        dockerUsername (username used in docker login comamand)
        dockerPassword (password used in docker login command)
        reportDirectory (full path where script should place reports)
        tempDirectory (full path where script should place temp files)
        needCleanup (True - remove temp files after each step, False - do not remove any files)
        scanType (singleImage - scans a single image, imageList - scans a list of images)

        Optional Variables:
        previouslyScannedFile (full path to a previous report)
        imageToScan (requires scanType=SingleImage, name of single image to scan)
        repoToScan (requires scanType=imageList, pull list of images from repo, ex: gerrit-server.domain.com:port/repo.git)
        fileToScan (requires scanType=imageList, file that contains list of images in repo, ex: path/to/images_list.yaml)
        """

        if os.environ.get('previouslyScannedFile') is not None:
            self.previouslyScannedFile = os.environ.get('previouslyScannedFile')
        else:
            self.previouslyScannedFile = None

        if os.environ.get('dockerServer') is not None:
            self.dockerServer = os.environ.get('dockerServer')
        else:
            print "Docker Server is not specified."
            sys.exit(0)

        if os.environ.get('gerritUsername') is not None:
            self.gerritUser = os.environ.get('gerritUsername')
        else:
            print "Gerrit Username is not specified."
            sys.exit(0)

        if os.environ.get('dockerUsername') is not None:
            self.dockerUser = os.environ.get('dockerUsername')
        else:
            print "Docker Username is not specified."
            sys.exit(0)

        if os.environ.get('dockerPassword') is not None:
            self.dockerPassword = os.environ.get('dockerPassword')
        else:
            print "Docker Password is not specified."
            sys.exit(0)

        if os.environ.get('reportDirectory') is not None:
            self.reportDirectory = os.environ.get('reportDirectory')
        else:
            print "Report Directory is not specified."
            sys.exit(0)

        if os.environ.get('tempDirectory') is not None:
            self.tempDirectory = os.environ.get('tempDirectory')
        else:
            print "Temporary Directory is not specified."
            sys.exit(0)

        if os.environ.get('needCleanup') is not None:
            self.needCleanup = os.environ.get('needCleanup')
        else:
            print "Cleanup mode is not specified."
            sys.exit(0)

        if os.environ.get('scanType') == 'singleImage':
            if os.environ.get('imageToScan') is not None:
                self.imageToScan = os.environ.get('imageToScan')
                self.scanType = os.environ.get('scanType')
            else:
                print "scanType is singleImage but imageToScan is not specified"
                sys.exit(0)

        elif os.environ.get('scanType') == 'imageList':
            self.scanType = os.environ.get('scanType')
            if self.gerritUser is not None:
                if os.environ.get('repoToScan') is not None:
                    self.repoToScan = os.environ.get('repoToScan')
                else:
                    print "scanType is set to imageList and gerrit username is specified but repoToScan is not specified"
                    sys.exit(0)
            if os.environ.get('fileToScan') is not None:
                if self.gerritUser is None:
                    print "Make sure fileToScan has the relative path to file"
                else:
                    print "Make sure filetoScan has just the file name"
                self.fileToScan = os.environ.get('fileToScan')
            else:
                print "scanType is set to imageList but fileToScan is not specified"
                sys.exit(0)
        else:
            print "A valid scanType is not specified.  Expect imageList or singleImage"
            sys.exit(0)

    def dockerLogin(self):
        """Execute docker login comamand."""

        try:
            subprocess.call(['docker', 'login', '--username', self.dockerUser,
                '--password', self.dockerPassword, self.dockerServer])
        except Exception as e:
            print e
            sys.exit(0)

    def createTempDirectories(self):
        """Create temporary directories for reports and tarballs"""
        try:
            os.makedirs(self.reportDirectory)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        try:
            os.makedirs(self.tempDirectory)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

    def getPreviouslyScannedLayers(self):
        """Get list of layers scanned in a previous report.

        Determine if ClamAV version and ClamAV virus definitions have changed.
        If they have, run a full scan.  If they have not, parse the previously
        generated report for a list of layers.  Do not scan those layers during
        this scan if the layer and virus information are both unchanged.
        """

        if self.previouslyScannedFile:
            with open(self.previouslyScannedFile, 'r') as stream:
                try:
                    f = yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    print(exc)
                    sys.exit(0)
            if self.clamav_version != f['clamAV_version'] or self.clamav_definitions != f['clamAV_definitions']:
                print "Running full scan as ClamAV version or definitions have changed."

            else:
                print "ClamAV version and definitions have not changed.  Ignoring previously scanned images"
                for imageID in f['images']:
                    imageName = imageID.keys()[0]
                    for layerID in imageID[imageName]['layers']:
                        if layerID not in self.scannedLayers:
                            self.scannedLayers.append(layerID)

    def getImagesToScan(self):
        """Determine which image(s) need to be scanned.

        If scanning a list of images, clone the repo containing that list of
        images.  Parse the specific file containing the images to build a list
        of image names.

        If scanning a single image create a list with the correct image name.

        Return the generated list for the scanner to loop over.
        """

        self.imageList = []
        if self.scanType == 'imageList':
            if self.gerritUser is not None:
                cloneLink = 'ssh://%s@%s' % (self.gerritUser, self.repoToScan)
                tempGitDirectory = tempfile.mkdtemp()
                git.Repo.clone_from(cloneLink, tempGitDirectory, branch='master',
                    depth=1)
                imagesFilePath = os.path.join(tempGitDirectory, self.fileToScan)
            else:
                imagesFilePath = self.fileToScan
            with open(imagesFilePath, 'r') as stream:
                try:
                    f = yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    print(exc)
                    sys.exit(0)
            for imageName in f['data']['images_refs']['images'].values():
                if imageName.find("DOCKER_") != -1:
                    dockerDomain = os.environ.get('dockerDomain')
                    dockerOpenDomain = os.environ.get('dockerOpenDomain')
                    image=imageName.replace("DOCKER_DOMAIN", dockerDomain).replace(
                        "DOCKER_OPEN_DOMAIN", dockerOpenDomain)
                    self.imageList.append(image)
                else:
                    self.imageList.append(imageName)
            if self.gerritUser is not None:        
                shutil.rmtree(tempGitDirectory)
        else:
            self.imageList.append(self.imageToScan)

    def saveImageAsTar(self, image_name):
        """Perform docker pull and docker save (as tar) commands.

        Special characters may be present in image name, replace them with '.'
        and save the image roughly as (image_name).tar

        If encountering errors at this step, ensure docker login credentials are
        correct, and the user has appropriate permissions.
        """

        tar_path = '%s/%s.tar' % (self.tempDirectory,
            image_name.replace('/','.').replace(':','.').replace('@','.'))
        tarball = open(tar_path, 'w')
        subprocess.call(['docker', 'pull', image_name])
        subprocess.call(['docker', 'save', image_name], stdout=tarball)

        return tar_path

    def scanLayer(self, imageID, layerID, layer_path):
        """Scan individual layer with ClamAV and report results

        Each layer should be scanned individually as some images may have common
        base layers this approach will speed up overall scan time without
        sacrificing security.  Count each layerID to later determine if each
        layer is unique or is a common base layer across multiple images.
        Append important information to log file, saved as (layer_id).log
        """

        # Update "seen" counter for each layer
        if layerID in self.layerList:
            self.layerList[layerID] += 1
        else:
            self.layerList[layerID] = 1

        # Docker images can have layers in common, do not repeat scan of layers
        if layerID not in self.scannedLayers:
            scanTime = datetime.datetime.utcnow()

            # Scan layer directory using ClamAV and log results
            log_path = '%s/%s.log' % (self.reportDirectory, layerID)
            subprocess.call(['clamscan', '--recursive', '--verbose',
                '--log=%s' % log_path, layer_path])

            # ClamAV generated a log, append important information.
            logFile = open(log_path, 'a+')
            logFile.write('Layer ID: %s\n' % layerID)
            logFile.write('Scan Time: %s\n' % str(scanTime))
            logFile.write('ClamAV Version: %s\n' % self.clamav_version)
            logFile.write('ClamAV Definitions: %s\n' % self.clamav_definitions)
            logFile.close()

            # Add this layer to list of previously scanned layers.
            self.scannedLayers.append(layerID)

    def removeTempFiles(self, dir_path, tar_path):
        """Remove temporary files generated by script if required by user."""

        if self.needCleanup == "True":
            shutil.rmtree(dir_path)
            os.remove(tar_path)

    def scanImages(self):
        """Scan each image and add the results to the yaml reports

        Using the list of images to scan, execute the docker pull/save commands,
        then extract the nested tar file into a directory structure for ClamAV
        to scan (ClamAV does not scan archives directly).

        Loop over the list of layers in each image, skip the layer if it has
        already been scanned.  Count the number of times the layer was seen, and
        if needed remove temporary files generated by script.

        Update yaml report.
        """

        for imageID in scanner.imageList:
            # Initialize report for this image to go into final YAML report
            image_results = {imageID: {'layers': [], 'unique_image': True}}

            # Save this image, extract it, and get the path to the directory
            tar_path = scanner.saveImageAsTar(imageID)
            dir_path = os.path.abspath(tar_path.replace('.tar', ''))
            extractnested.ExtractNested(os.path.abspath(tar_path))

            for layerID in os.listdir(dir_path):
                layer_path = os.path.join(dir_path, layerID)

                # Layers are directories, scan the layers and their contents.
                if os.path.isdir(layer_path):
                    scanner.scanLayer(imageID, layerID, layer_path)
                    image_results[imageID]['layers'].append(layerID)

            # Add results of this image to YAML report, remove temp files.
            self.yaml_report['images'].append(image_results)
            scanner.removeTempFiles(dir_path, tar_path)

    def determineUniqueImages(self):
        """Determine if each image has any common base layers.

        Check each image to see if any of its layers were seen more than once
        during the entire scan.  If so this is not a unique image as it shares
        at least one common base layer.
        """

        for imageID in self.yaml_report['images']:
            imageName = imageID.keys()[0]
            for layerID in imageID[imageName]['layers']:
                if self.layerList[layerID] > 1:
                    imageID[imageName]['unique_image'] = False

    def generateReport(self):
        """Generate YAML report."""

        endTime = datetime.datetime.utcnow()
        self.yaml_report['endTime'] = endTime
        report_path = '%s/clamAV_results-%s.yaml' % (
            os.path.abspath(self.reportDirectory),
            endTime.strftime("%Y%m%d-%H%M%S"))
        with open(report_path, 'w') as outfile:
            yaml.dump(self.yaml_report, outfile, default_flow_style=False)
        outfile.close()

if __name__ == '__main__':
    scanner = Scanner()
    scanner.getEnvironmentVariables()
    scanner.createTempDirectories()
    scanner.dockerLogin()
    scanner.getPreviouslyScannedLayers()
    scanner.getImagesToScan()
    scanner.scanImages()
    scanner.determineUniqueImages()
    scanner.generateReport()
