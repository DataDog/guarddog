import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Optional, Set, List
import requests
from bs4 import BeautifulSoup

from guarddog.analyzer.metadata.typosquatting import TyposquatDetector
from guarddog.utils.config import TOP_PACKAGES_CACHE_LOCATION

log = logging.getLogger("guarddog")


class MavenTyposquatDetector(TyposquatDetector):
    """Detector for typosquatting attacks for Maven packages. Checks for distance one Levenshtein,
    one-off character swaps, permutations around hyphens, and substrings.

    Attributes:
        popular_packages (set): set of top Maven packages with 30-day caching,
          stored in resources/top_maven_packages.json and updated every 30 days
    """

    def _get_top_packages(self) -> set:
        """
        Gets Maven packages using the same 30-day caching pattern as PyPI and NPM.
        Follows exact same architecture - caching logic in detector, not external utility.
        
        Returns:
            set: Set of popular Maven packages in "groupId:artifactId" format
        """
        top_packages_filename = "top_maven_packages.json"

        resources_dir = TOP_PACKAGES_CACHE_LOCATION
        if resources_dir is None:
            resources_dir = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "resources")
            )

        top_packages_path = os.path.join(resources_dir, top_packages_filename)

        top_packages_information = None

        # Check if file exists and is recent (< 30 days old) - same pattern as PyPI/NPM
        if top_packages_filename in os.listdir(resources_dir):
            update_time = datetime.fromtimestamp(os.path.getmtime(top_packages_path))

            if datetime.now() - update_time <= timedelta(days=30):
                log.debug(f"Using cached Maven packages from {top_packages_path}")
                with open(top_packages_path, "r") as top_packages_file:
                    top_packages_information = json.load(top_packages_file)
                    
                # If cached file is empty, treat it as no cache and fetch dynamically
                if not top_packages_information:
                    log.info("Cached file is empty, triggering dynamic generation...")
                    top_packages_information = None

        # If no recent cache or empty cache, try to fetch dynamically and update the file
        if top_packages_information is None:
            log.info("Fetching Maven packages dynamically using Python scraper...")
            
            try:
                dynamic_packages = self._fetch_maven_packages_with_python()
                if dynamic_packages:
                    # Update the resources file directly - same as PyPI/NPM
                    top_packages_information = sorted(list(dynamic_packages))
                    with open(top_packages_path, "w") as f:
                        json.dump(top_packages_information, f, ensure_ascii=False, indent=2)
                    log.info(f"Updated {top_packages_path} with {len(top_packages_information)} packages")
                else:
                    # If scraping fails, read existing file
                    log.warning("Python scraper failed, using existing cached data")
                    if os.path.exists(top_packages_path):
                        with open(top_packages_path, "r") as top_packages_file:
                            top_packages_information = json.load(top_packages_file)
                            
            except Exception as e:
                log.warning(f"Dynamic fetching failed: {e}")
                # Fallback to existing file
                if os.path.exists(top_packages_path):
                    with open(top_packages_path, "r") as top_packages_file:
                        top_packages_information = json.load(top_packages_file)

        # Final fallback if everything fails
        if top_packages_information is None:
            log.warning("All package sources failed, using minimal essential packages")
            top_packages_information = list(self._get_essential_maven_packages())

        return set(top_packages_information)

    def _scrape_mvn_popular_page(self, page: int) -> List[str]:
        """
        Scrape popular Maven packages from mvnrepository.com for a specific page.
        Python equivalent of the Go getMvnPopularPage function.
        
        Args:
            page (int): Page number to scrape
            
        Returns:
            List[str]: List of package names in "groupId:artifactId" format
        """
        url = f"https://mvnrepository.com/popular?p={page}"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            packages = set()
            
            # Look for "Top Projects" section
            found_top_projects = False
            for h1 in soup.find_all('h1'):
                if h1.get_text().strip() == "Top Projects":
                    found_top_projects = True
                    break
            
            if found_top_projects:
                # Find all artifact links in the format /artifact/groupId/artifactId
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('/artifact/'):
                        parts = href.split('/')
                        if len(parts) == 4:  # /artifact/groupId/artifactId
                            packages.add(f"{parts[2]}:{parts[3]}")
            
            return list(packages)
            
        except Exception as e:
            log.warning(f"Failed to scrape mvnrepository.com page {page}: {e}")
            return []

    def _get_deps_dev_default_version(self, package_name: str) -> Optional[str]:
        """
        Get default version from deps.dev API.
        Python equivalent of the Go getDepsDevDefaultVersion function.
        
        Args:
            package_name (str): Package name in "groupId:artifactId" format
            
        Returns:
            Optional[str]: Default version if found, None otherwise
        """
        url = f"https://api.deps.dev/v3alpha/systems/maven/packages/{package_name}"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                return None
                
            data = response.json()
            for version in data.get('versions', []):
                if version.get('isDefault'):
                    return version.get('versionKey', {}).get('version')
                    
        except Exception as e:
            log.debug(f"Failed to get default version for {package_name}: {e}")
            
        return None

    def _get_deps_dev_dependencies(self, package_name: str, version: str) -> List[str]:
        """
        Get dependencies from deps.dev API.
        Python equivalent of the Go getDepsDevDependencies function.
        
        Args:
            package_name (str): Package name in "groupId:artifactId" format
            version (str): Package version
            
        Returns:
            List[str]: List of dependency package names
        """
        url = f"https://api.deps.dev/v3alpha/systems/maven/packages/{package_name}/versions/{version}:dependencies"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                return []
                
            data = response.json()
            dependencies = []
            
            for node in data.get('nodes', []):
                version_key = node.get('versionKey', {})
                if version_key.get('system') == 'maven':
                    dep_name = version_key.get('name', '')
                    if dep_name:
                        dependencies.append(dep_name)
                        
            return dependencies
            
        except Exception as e:
            log.debug(f"Failed to get dependencies for {package_name}@{version}: {e}")
            
        return []

    def _fetch_maven_packages_with_python(self) -> Set[str]:
        """
        Pure Python implementation of Maven package fetching.
        Replaces the Go script with equivalent Python functionality.
        
        Returns:
            Set[str]: Set of packages if successful, empty set if failed
        """
        all_packages = set()
        
        log.info("Scraping Maven packages from mvnrepository.com...")
        
        # Strategy 1: Scrape mvnrepository.com popular pages (15 pages for good coverage)
        try:
            for page in range(1, 16):  # Pages 1-15
                packages = self._scrape_mvn_popular_page(page)
                if packages:
                    all_packages.update(packages)
                    log.debug(f"Scraped {len(packages)} packages from page {page}")
                else:
                    # If we get no packages, we might have hit the end
                    break
                
                time.sleep(0.5)
                
            log.info(f"Scraped {len(all_packages)} packages from mvnrepository.com")
            
        except Exception as e:
            log.warning(f"Failed to scrape mvnrepository.com: {e}")
        
        # Strategy 2: Expand with dependencies using deps.dev API
        if all_packages:
            try:
                log.info("Expanding package list with dependencies from deps.dev...")
                base_packages = list(all_packages)[:50]  # Limit to avoid too many API calls
                dependency_packages = set()
                
                for package in base_packages:
                    version = self._get_deps_dev_default_version(package)
                    if version:
                        deps = self._get_deps_dev_dependencies(package, version)
                        dependency_packages.update(deps)
                    
                
                    time.sleep(0.1)
                
                all_packages.update(dependency_packages)
                log.info(f"Added {len(dependency_packages)} dependency packages")
                
            except Exception as e:
                log.warning(f"Failed to expand with dependencies: {e}")
        
        # Strategy 3: Always include essential packages
        essential_packages = self._get_essential_maven_packages()
        all_packages.update(essential_packages)
        
        log.info(f"Final package count: {len(all_packages)} (including {len(essential_packages)} essential)")
        return all_packages

    def _get_essential_maven_packages(self) -> Set[str]:
        """
        Returns a curated set of essential Maven packages as final fallback.
        These are the most critical packages that should always be included.
        
        Returns:
            Set[str]: Essential Maven packages
        """
        return {
            # Spring Boot ecosystem (most popular)
            "org.springframework.boot:spring-boot-starter-parent",
            "org.springframework.boot:spring-boot-starter-web",
            "org.springframework.boot:spring-boot-starter-data-jpa", 
            "org.springframework.boot:spring-boot-starter-test",
            "org.springframework.boot:spring-boot-starter-security",
            "org.springframework.boot:spring-boot-starter-actuator",
            
            # Core Spring
            "org.springframework:spring-core",
            "org.springframework:spring-context",
            "org.springframework:spring-web",
            "org.springframework:spring-webmvc",
            
            # Testing
            "org.junit.jupiter:junit-jupiter",
            "org.junit.jupiter:junit-jupiter-api",
            "org.junit.jupiter:junit-jupiter-engine",
            "org.mockito:mockito-core",
            "org.testng:testng",
            
            # Logging
            "org.slf4j:slf4j-api",
            "ch.qos.logback:logback-classic",
            "org.apache.logging.log4j:log4j-core",
            
            # JSON processing
            "com.fasterxml.jackson.core:jackson-core",
            "com.fasterxml.jackson.core:jackson-databind",
            "com.google.code.gson:gson",
            
            # Utilities
            "com.google.guava:guava",
            "org.apache.commons:commons-lang3",
            "org.projectlombok:lombok",
            
            # Database
            "mysql:mysql-connector-java",
            "org.postgresql:postgresql",
            "com.h2database:h2",
            "org.hibernate.orm:hibernate-core",
            
            # HTTP clients
            "org.apache.httpcomponents:httpclient",
            "com.squareup.okhttp3:okhttp",
        }

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        """
        Uses a Maven package's information to determine if the
        package is attempting a typosquatting attack

        Args:
            package_info (dict): dictionary containing Maven package information
                with 'info' key containing 'groupid' and 'artifactid'
            name (str): The name of the package in format "groupId:artifactId"

        Returns:
            Tuple[bool, Optional[str]]: True if package is typosquatted,
               along with a message indicating the similar package name.
               False if not typosquatted and None
        """
        # Construct the full package name from package_info if name is not provided
        if name is None:
            group_id = package_info.get("info", {}).get("groupid", "")
            artifact_id = package_info.get("info", {}).get("artifactid", "")
            if group_id and artifact_id:
                name = f"{group_id}:{artifact_id}"
            else:
                return False, "Could not determine package name from package info"

        log.debug(f"Running typosquatting heuristic on Maven package {name}")
        similar_package_names = self.get_typosquatted_package(name)
        if len(similar_package_names) > 0:
            return True, TyposquatDetector.MESSAGE_TEMPLATE % ", ".join(
                similar_package_names
            )
        return False, None





    def _get_confused_forms(self, package_name) -> list:
        """
        Gets confused terms for Maven packages
        Confused terms are:
            - org.apache.* to org.springframework.* swaps (or vice versa)
            - com.google.* to com.apache.* swaps  
            - Group ID hierarchy confusions (org.junit vs junit)
            - Common Maven group ID patterns and sub-groups
            - Artifact ID term swaps (core/api, spring/apache, etc.)

        Args:
            package_name (str): name of the package in format "groupId:artifactId"

        Returns:
            list: list of confused terms
        """
        confused_forms = []

        if ":" not in package_name:
            return confused_forms

        group_id, artifact_id = package_name.split(":", 1)

        # Enhanced group ID confusions with pattern matching
        group_id_patterns = {
            # Apache ecosystem confusions
            "org.apache": ["org.springframework", "com.apache"],
            "org.apache.commons": ["org.springframework", "com.google.common", "org.apache"],
            "org.apache.logging": ["org.slf4j", "ch.qos.logback"],
            "org.apache.httpcomponents": ["com.squareup.okhttp3", "org.springframework.web"],
            
            # Spring ecosystem confusions  
            "org.springframework": ["org.apache", "org.apache.commons", "com.springframework"],
            "org.springframework.boot": ["org.springframework", "org.apache.commons"],
            "org.springframework.data": ["org.hibernate", "org.apache.commons"],
            
            # Google ecosystem confusions
            "com.google": ["com.apache", "org.google", "com.google.guava"],
            "com.google.guava": ["org.apache.commons", "com.google"],
            "com.google.code": ["org.apache", "com.google"],
            
            # Testing framework confusions
            "org.junit": ["junit", "com.junit", "org.testng"],
            "junit": ["org.junit", "org.testng"],
            "org.testng": ["org.junit", "junit"],
            "org.mockito": ["com.mockito", "org.junit", "org.testng"],
            
            # Logging framework confusions
            "org.slf4j": ["ch.qos.logback", "org.apache.logging.log4j"],
            "ch.qos.logback": ["org.slf4j", "org.apache.logging.log4j"],
            "org.apache.logging.log4j": ["org.slf4j", "ch.qos.logback"],
            
            # Hibernate/JPA confusions
            "org.hibernate": ["com.hibernate", "org.springframework.data", "javax.persistence"],
            "javax.persistence": ["org.hibernate", "org.springframework.data"],
            
            # Jackson confusions
            "com.fasterxml.jackson": ["com.fasterxml.jackson.core", "org.codehaus.jackson"],
            "com.fasterxml.jackson.core": ["com.fasterxml.jackson", "org.codehaus.jackson"],
            "com.fasterxml": ["com.fasterxml.jackson"],
            
            # Database driver confusions
            "mysql": ["org.mysql", "com.mysql"],
            "org.postgresql": ["postgresql", "com.postgresql"],
        }

        # Generate confused forms based on exact and pattern matches
        for pattern_group, confused_groups in group_id_patterns.items():
            if group_id == pattern_group:
                # Exact match
                for confused_group in confused_groups:
                    confused_forms.append(f"{confused_group}:{artifact_id}")
            elif group_id in confused_groups:
                # Reverse mapping
                confused_forms.append(f"{pattern_group}:{artifact_id}")
            elif group_id.startswith(pattern_group + "."):
                # Sub-group pattern matching (e.g., org.apache.* → org.springframework.*)
                for confused_group in confused_groups:
                    if not confused_group.startswith(group_id[:group_id.rfind(".")]):
                        confused_forms.append(f"{confused_group}:{artifact_id}")

        # Handle hierarchical group ID simplifications/expansions
        group_parts = group_id.split(".")
        if len(group_parts) > 2:
            # Try simplified versions (e.g., org.apache.commons → org.apache)
            simplified = ".".join(group_parts[:-1])
            confused_forms.append(f"{simplified}:{artifact_id}")
            
            # Try root level (e.g., org.apache.commons → apache)
            if len(group_parts) >= 2:
                root = group_parts[-2]  # Get the main organization name
                confused_forms.append(f"{root}:{artifact_id}")

        # Handle artifact ID pattern confusions
        artifact_terms = artifact_id.split("-")
        
        # Enhanced artifact term confusions
        artifact_confusions = {
            "spring": ["apache", "hibernate"],
            "apache": ["spring", "commons"],
            "core": ["api", "common", "base"],
            "api": ["core", "common", "interface"],
            "common": ["core", "api", "utils"],
            "utils": ["common", "core", "tools"],
            "client": ["server", "api", "core"],
            "server": ["client", "api", "core"],
            "web": ["rest", "http", "api"],
            "rest": ["web", "http", "api"],
            "boot": ["core", "spring", "auto"],
            "auto": ["boot", "config", "core"],
            "test": ["testing", "junit", "mock"],
            "mock": ["test", "mockito", "fake"],
            "starter": ["boot", "spring", "auto"],
        }
        
        for i, term in enumerate(artifact_terms):
            for original_term, confused_terms in artifact_confusions.items():
                if original_term in term:
                    # Replace term with confused versions
                    for confused_term in confused_terms:
                        new_term = term.replace(original_term, confused_term)
                        if new_term != term:  # Only add if it actually changed
                            replaced_artifact = artifact_terms[:i] + [new_term] + artifact_terms[i + 1:]
                            confused_forms.append(f"{group_id}:{'-'.join(replaced_artifact)}")

        # Remove duplicates while preserving order
        seen = set()
        unique_confused_forms = []
        for form in confused_forms:
            if form not in seen and form != package_name:  # Don't include the original package
                seen.add(form)
                unique_confused_forms.append(form)

        return unique_confused_forms


if __name__ == "__main__":
    detector = MavenTyposquatDetector()
    packages = detector._get_top_packages()
