#!/usr/bin/env python3
"""
S3 Bucket Inspector
A tool to scan for publicly accessible cloud storage buckets (S3, Azure, GCP)
and detect misconfigurations and unauthorized access.
"""

import os
import json
import argparse
import re
import concurrent.futures
import logging
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

# Cloud provider SDKs
import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError, AzureError
from google.cloud import storage
from google.cloud.exceptions import NotFound, GoogleCloudError

# Additional utilities
import requests
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.table import Table
from rich.text import Text
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("debug.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Rich console for pretty output
console = Console()

class BucketInspector:
    """Main class for the S3 Bucket Inspector tool."""
    
    def __init__(self, domains: List[str], output_file: str = None, 
                 verbose: bool = False, threads: int = 10,
                 disable_aws: bool = False, disable_azure: bool = False, disable_gcp: bool = False,
                 extra_wordlist: List[str] = None, scan_accounts: List[str] = None):
        """Initialize the bucket inspector with target domains."""
        self.domains = domains
        self.output_file = output_file
        self.verbose = verbose
        self.threads = threads
        self.disable_aws = disable_aws
        self.disable_azure = disable_azure
        self.disable_gcp = disable_gcp
        self.extra_wordlist = extra_wordlist or []
        self.scan_accounts = scan_accounts or []
        self.results = {
            "aws": [],
            "azure": [],
            "gcp": []
        }
        self.potential_buckets = set()
        
        # Initialize cloud clients
        self._init_aws_client()
        self._init_azure_client()
        self._init_gcp_client()
    
    def _init_aws_client(self):
        """Initialize AWS S3 client with unsigned config for anonymous access."""
        if self.disable_aws:
            self.aws_enabled = False
            return
            
        try:
            # Use unsigned config to allow anonymous access to public buckets
            unsigned_config = Config(signature_version=UNSIGNED)
            self.s3_client = boto3.client('s3', config=unsigned_config)
            self.aws_enabled = True
        except Exception as e:
            console.print(f"[red]Error initializing AWS client: {str(e)}[/red]")
            self.aws_enabled = False
    
    def _init_azure_client(self):
        """Initialize Azure Blob Storage client."""
        if self.disable_azure:
            self.azure_enabled = False
            return
            
        connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
        if connection_string:
            try:
                self.azure_client = BlobServiceClient.from_connection_string(connection_string)
                self.azure_enabled = True
            except Exception as e:
                console.print(f"[red]Error initializing Azure client: {str(e)}[/red]")
                self.azure_enabled = False
        else:
            console.print("[yellow]Azure connection string not found. Azure scanning will be limited to public access checks.[/yellow]")
            self.azure_enabled = True  # Still enable basic checks without credentials
    
    def _init_gcp_client(self):
        """Initialize Google Cloud Storage client."""
        if self.disable_gcp:
            self.gcp_enabled = False
            return
            
        try:
            self.gcp_client = storage.Client()
            self.gcp_enabled = True
        except Exception as e:
            console.print(f"[yellow]GCP credentials not found. GCP scanning will be limited to public access checks.[/yellow]")
            self.gcp_enabled = True  # Still enable basic checks without credentials
    
    def _parse_domain_for_bucket_names(self, domain: str) -> List[str]:
        """Parse domain to extract potential bucket names, handling S3 URLs properly."""
        bucket_names = []
        
        # Check if this is an S3 URL (e.g., commoncrawl.s3.amazonaws.com)
        s3_url_pattern = re.compile(r'^([^.]+)\.s3\.amazonaws\.com$')
        match = s3_url_pattern.match(domain.lower())
        if match:
            # If it's an S3 URL, use the bucket name directly
            bucket_name = match.group(1)
            bucket_names.append(bucket_name)
            return bucket_names
        
        # For regular domains, generate a comprehensive list of potential bucket names
        domain_parts = domain.lower().replace("www.", "").split(".")
        company_name = domain_parts[0]
        
        # Basic permutations
        bucket_names = [
            domain.replace(".", "-"),
            domain.replace(".", ""),
            company_name,
            f"{company_name}-backup",
            f"{company_name}-files",
            f"{company_name}-data",
            f"{company_name}-media",
            f"{company_name}-static",
            f"{company_name}-assets",
            f"{company_name}-public",
            f"{company_name}-private",
            f"{company_name}-dev",
            f"{company_name}-prod",
            f"{company_name}-stage",
            f"{company_name}-test",
            f"{company_name}-images",
            f"{company_name}-documents",
            f"{company_name}-uploads",
            f"{company_name}-content",
            f"{company_name}-storage"
        ]
        
        # Enhanced permutations for better discovery
        # Cloud provider specific prefixes/suffixes
        cloud_variations = [
            f"{company_name}-aws",
            f"{company_name}-azure",
            f"{company_name}-gcp",
            f"{company_name}-s3",
            f"{company_name}-blob",
            f"{company_name}-cloud",
            f"aws-{company_name}",
            f"azure-{company_name}",
            f"gcp-{company_name}",
            f"s3-{company_name}",
            f"blob-{company_name}",
        ]
        bucket_names.extend(cloud_variations)
        
        # Region-specific variations
        regions = ["us", "eu", "ap", "sa", "ca", "me", "af"]
        for region in regions:
            bucket_names.append(f"{company_name}-{region}")
            bucket_names.append(f"{region}-{company_name}")
            bucket_names.append(f"{company_name}-{region}-east")
            bucket_names.append(f"{company_name}-{region}-west")
            bucket_names.append(f"{company_name}-{region}-north")
            bucket_names.append(f"{company_name}-{region}-south")
            bucket_names.append(f"{company_name}-{region}-central")
        
        # Common environment and purpose combinations
        envs = ["dev", "test", "staging", "uat", "qa", "prod", "production", "demo"]
        purposes = ["storage", "backup", "archive", "media", "static", "data", "files", "assets", "uploads"]
        
        for env in envs:
            bucket_names.append(f"{company_name}-{env}")
            for purpose in purposes:
                bucket_names.append(f"{company_name}-{env}-{purpose}")
                bucket_names.append(f"{company_name}-{purpose}-{env}")
        
        # Add company name with years
        current_year = datetime.now().year
        for year in range(current_year - 10, current_year + 1):
            bucket_names.append(f"{company_name}-{year}")
            bucket_names.append(f"{company_name}{year}")
        
        # Add any extra names from wordlist if provided
        if self.extra_wordlist:
            for word in self.extra_wordlist:
                bucket_names.append(f"{company_name}-{word}")
                bucket_names.append(f"{word}-{company_name}")
                bucket_names.append(word)
        
        # Remove duplicates
        return list(set(bucket_names))
    
    def _scan_aws_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """Scan an AWS S3 bucket for public access."""
        result = {
            "bucket_name": bucket_name,
            "provider": "AWS",
            "exists": False,
            "public": False,
            "public_files": [],
            "issues": [],
            "bucket_policy": None
        }
        
        try:
            # Check if bucket exists by trying to list objects (anonym)
            response = self.s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
            result["exists"] = True
            
            # If we can list objects anonymously, the bucket is definitely public
            if 'Contents' in response:
                result["public"] = True
                result["issues"].append("Anonymous users can list bucket contents")
                
                # Save the listed objects
                for obj in response.get('Contents', []):
                    url = f"https://{bucket_name}.s3.amazonaws.com/{obj['Key']}"
                    result["public_files"].append({
                        "key": obj['Key'],
                        "url": url,
                        "size": obj['Size'],
                        "last_modified": obj['LastModified'].isoformat()
                    })
            
            # Also try to check bucket ACL
            try:
                acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' and grant.get('Permission') in ['READ', 'WRITE', 'FULL_CONTROL']:
                        result["public"] = True
                        result["issues"].append(f"Bucket has {grant.get('Permission')} permission for AllUsers")
            except ClientError:
                pass
            
            # Try to check bucket policy
            try:
                policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_json = json.loads(policy['Policy'])
                result["bucket_policy"] = policy_json
                
                # Basic check for public policy
                if '"Principal": "*"' in policy['Policy']:
                    result["public"] = True
                    result["issues"].append("Bucket policy allows access to all users (*)")
            except ClientError:
                pass
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '403':
                result["exists"] = True
                result["issues"].append("Access denied - bucket exists but requires authentication")
            elif error_code != '404':
                result["exists"] = True
                result["issues"].append(f"Error checking bucket: {error_code}")
        
        return result
    
    def _scan_azure_storage(self, account_name: str) -> Dict[str, Any]:
        """Scan an Azure storage account for public access."""
        result = {
            "account_name": account_name,
            "provider": "Azure",
            "exists": False,
            "public": False,
            "public_containers": [],
            "issues": []
        }
        
        try:
            # Check if account exists by trying to access it
            url = f"https://{account_name}.blob.core.windows.net/"
            response = requests.head(url, timeout=5)
            
            if response.status_code != 404:
                result["exists"] = True
                
                # Try to list containers if we have a client connection
                if hasattr(self, 'azure_client') and self.azure_client:
                    try:
                        for container in self.azure_client.list_containers(name_starts_with=""):
                            container_client = self.azure_client.get_container_client(container["name"])
                            acl = container_client.get_container_access_policy()
                            
                            if container.get("public_access") is not None:
                                result["public"] = True
                                result["public_containers"].append({
                                    "name": container["name"],
                                    "access_level": container.get("public_access", "private"),
                                    "url": f"https://{account_name}.blob.core.windows.net/{container['name']}"
                                })
                                result["issues"].append(f"Container '{container['name']}' has public access level: {container.get('public_access')}")
                    except Exception as e:
                        if "AuthenticationFailed" not in str(e):
                            result["issues"].append(f"Error listing containers: {str(e)}")
                else:
                    # Even without client, try to check for common container names
                    common_containers = ["public", "data", "assets", "images", "documents", "media"]
                    for container_name in common_containers:
                        container_url = f"https://{account_name}.blob.core.windows.net/{container_name}"
                        try:
                            container_resp = requests.head(container_url, timeout=5)
                            if container_resp.status_code != 404:
                                result["public"] = True
                                result["public_containers"].append({
                                    "name": container_name,
                                    "access_level": "unknown",
                                    "url": container_url
                                })
                                result["issues"].append(f"Container '{container_name}' appears to be publicly accessible")
                        except requests.RequestException:
                            pass
        except requests.RequestException:
            pass
        
        return result
    
    def _scan_gcp_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """Scan a Google Cloud Storage bucket for public access."""
        result = {
            "bucket_name": bucket_name,
            "provider": "GCP",
            "exists": False,
            "public": False,
            "public_access": [],
            "issues": []
        }
        
        # First try with direct GCP client if available
        if hasattr(self, 'gcp_client') and self.gcp_client:
            try:
                bucket = self.gcp_client.bucket(bucket_name)
                bucket.reload()
                result["exists"] = True
                
                # Check IAM policies
                policy = bucket.get_iam_policy()
                
                for binding in policy.bindings:
                    if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                        result["public"] = True
                        result["public_access"].append({
                            "role": binding["role"],
                            "members": binding["members"]
                        })
                        result["issues"].append(f"Bucket has public access through IAM role: {binding['role']}")
                
                # Check default ACLs
                if bucket.iam_configuration.bucket_policy_only_enabled:
                    result["issues"].append("Bucket uses uniform bucket-level access")
                else:
                    default_object_acl = bucket.default_object_acl
                    for entry in default_object_acl:
                        if entry["entity"] in ["allUsers", "allAuthenticatedUsers"]:
                            result["public"] = True
                            result["issues"].append(f"Default object ACL allows {entry['entity']} with permission {entry['role']}")
                
            except NotFound:
                pass
            except GoogleCloudError as e:
                if "403" in str(e):
                    result["exists"] = True
                    result["issues"].append("Access denied - bucket exists but requires authentication")
        
        # If we couldn't check with the client or bucket wasn't found, try direct HTTP access
        if not result["exists"]:
            try:
                # Try accessing the bucket via HTTPS
                url = f"https://storage.googleapis.com/{bucket_name}"
                response = requests.get(url, timeout=5)
                
                if response.status_code != 404:
                    result["exists"] = True
                    
                    # Try to access a sample object to check public access
                    if response.status_code == 200:
                        result["public"] = True
                        result["issues"].append("Bucket is publicly accessible via HTTP")
            except requests.RequestException:
                pass
        
        return result
    
    def _discover_account_buckets(self):
        """Discover all buckets in cloud accounts using authenticated API calls."""
        account_buckets_found = 0
        
        # AWS S3 bucket discovery
        if self.aws_enabled and 'aws' in self.scan_accounts:
            try:
                # Check if we have valid credentials (this would fail with anonymous credentials)
                caller_identity = boto3.client('sts').get_caller_identity()
                account_id = caller_identity['Account']
                
                console.print(f"[green]Discovering all buckets in AWS account {account_id}...[/green]")
                
                # List all buckets in the account
                response = self.s3_client.list_buckets()
                aws_buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]
                
                if aws_buckets:
                    self.potential_buckets.update(aws_buckets)
                    account_buckets_found += len(aws_buckets)
                    console.print(f"[green]Found {len(aws_buckets)} buckets in AWS account[/green]")
            except Exception as e:
                console.print(f"[yellow]Could not discover AWS buckets: {str(e)}[/yellow]")
                console.print(f"[yellow]Make sure you have valid AWS credentials set up[/yellow]")
        
        # Azure Blob Storage discovery
        if self.azure_enabled and 'azure' in self.scan_accounts:
            try:
                if hasattr(self, 'azure_client') and self.azure_client:
                    console.print(f"[green]Discovering all storage accounts in Azure...[/green]")
                    
                    # This is a simplified approach - in a real implementation, you would
                    # iterate through subscriptions and resource groups
                    from azure.mgmt.storage import StorageManagementClient
                    from azure.identity import DefaultAzureCredential
                    
                    # Get subscription ID from environment or config
                    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
                    if subscription_id:
                        # Create a storage management client
                        credential = DefaultAzureCredential()
                        storage_client = StorageManagementClient(credential, subscription_id)
                        
                        # List all storage accounts
                        azure_accounts = list(storage_client.storage_accounts.list())
                        azure_account_names = [account.name for account in azure_accounts]
                        
                        if azure_account_names:
                            self.potential_buckets.update(azure_account_names)
                            account_buckets_found += len(azure_account_names)
                            console.print(f"[green]Found {len(azure_account_names)} storage accounts in Azure[/green]")
                    else:
                        console.print(f"[yellow]Azure subscription ID not found. Set AZURE_SUBSCRIPTION_ID in environment variables.[/yellow]")
            except Exception as e:
                console.print(f"[yellow]Could not discover Azure storage accounts: {str(e)}[/yellow]")
                console.print(f"[yellow]Make sure you have valid Azure credentials set up[/yellow]")
        
        # Google Cloud Storage discovery
        if self.gcp_enabled and 'gcp' in self.scan_accounts:
            try:
                if hasattr(self, 'gcp_client') and self.gcp_client:
                    console.print(f"[green]Discovering all buckets in Google Cloud Storage...[/green]")
                    
                    # List all buckets in the project
                    gcp_buckets = list(self.gcp_client.list_buckets())
                    gcp_bucket_names = [bucket.name for bucket in gcp_buckets]
                    
                    if gcp_bucket_names:
                        self.potential_buckets.update(gcp_bucket_names)
                        account_buckets_found += len(gcp_bucket_names)
                        console.print(f"[green]Found {len(gcp_bucket_names)} buckets in Google Cloud Storage[/green]")
            except Exception as e:
                console.print(f"[yellow]Could not discover GCP buckets: {str(e)}[/yellow]")
                console.print(f"[yellow]Make sure you have valid GCP credentials set up[/yellow]")
        
        if account_buckets_found > 0:
            console.print(f"[green]Total buckets discovered from cloud accounts: {account_buckets_found}[/green]")
        else:
            console.print(f"[yellow]No buckets discovered from cloud accounts. Check your credentials or try domain-based scanning.[/yellow]")
        
        return account_buckets_found

    def scan_all_buckets(self):
        """Scan all potential buckets across cloud providers."""
        # First, try to discover buckets from cloud accounts if requested
        if self.scan_accounts:
            self._discover_account_buckets()
        
        # Then generate potential bucket names from domains
        for domain in self.domains:
            parsed_bucket_names = self._parse_domain_for_bucket_names(domain)
            self.potential_buckets.update(parsed_bucket_names)
        
        total_buckets = len(self.potential_buckets) * sum([
            1 if self.aws_enabled else 0,
            1 if self.azure_enabled else 0,
            1 if self.gcp_enabled else 0
        ])
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn()
        ) as progress:
            scan_task = progress.add_task("[cyan]Scanning buckets...", total=total_buckets)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                # AWS S3 scanning
                if self.aws_enabled:
                    aws_futures = {executor.submit(self._scan_aws_bucket, bucket): bucket for bucket in self.potential_buckets}
                    
                    for future in concurrent.futures.as_completed(aws_futures):
                        bucket = aws_futures[future]
                        try:
                            result = future.result()
                            if result["exists"]:
                                self.results["aws"].append(result)
                                if self.verbose and (result["public"] or result["issues"]):
                                    self._print_bucket_result(result)
                        except Exception as e:
                            if self.verbose:
                                console.print(f"[red]Error scanning AWS bucket {bucket}: {str(e)}[/red]")
                        progress.update(scan_task, advance=1)
                
                # Azure Blob Storage scanning
                if self.azure_enabled:
                    azure_futures = {executor.submit(self._scan_azure_storage, bucket): bucket for bucket in self.potential_buckets}
                    
                    for future in concurrent.futures.as_completed(azure_futures):
                        bucket = azure_futures[future]
                        try:
                            result = future.result()
                            if result["exists"]:
                                self.results["azure"].append(result)
                                if self.verbose and (result["public"] or result["issues"]):
                                    self._print_bucket_result(result)
                        except Exception as e:
                            if self.verbose:
                                console.print(f"[red]Error scanning Azure storage {bucket}: {str(e)}[/red]")
                        progress.update(scan_task, advance=1)
                
                # Google Cloud Storage scanning
                if self.gcp_enabled:
                    gcp_futures = {executor.submit(self._scan_gcp_bucket, bucket): bucket for bucket in self.potential_buckets}
                    
                    for future in concurrent.futures.as_completed(gcp_futures):
                        bucket = gcp_futures[future]
                        try:
                            result = future.result()
                            if result["exists"]:
                                self.results["gcp"].append(result)
                                if self.verbose and (result["public"] or result["issues"]):
                                    self._print_bucket_result(result)
                        except Exception as e:
                            if self.verbose:
                                console.print(f"[red]Error scanning GCP bucket {bucket}: {str(e)}[/red]")
                        progress.update(scan_task, advance=1)
    
    def _print_bucket_result(self, result: Dict[str, Any]):
        """Print a single bucket scan result to the console."""
        provider = result.get("provider", "Unknown")
        
        if provider == "AWS":
            bucket_name = result.get("bucket_name", "Unknown")
            console.print(f"[bold]{provider}: {bucket_name}[/bold]")
            
            if result.get("public", False):
                console.print("[red]Public: Yes[/red]")
            else:
                console.print("[green]Public: No[/green]")
            
            if result.get("issues", []):
                console.print("[yellow]Issues found:[/yellow]")
                for issue in result["issues"]:
                    console.print(f"  - {issue}")
            
            if result.get("public_files", []):
                console.print("[yellow]Public files:[/yellow]")
                for file in result["public_files"][:5]:  # Limit to 5 files
                    console.print(f"  - {file['key']} ({file['url']})")
                if len(result["public_files"]) > 5:
                    console.print(f"  ... and {len(result['public_files']) - 5} more files")
        
        elif provider == "Azure":
            account_name = result.get("account_name", "Unknown")
            console.print(f"[bold]{provider}: {account_name}[/bold]")
            
            if result.get("public", False):
                console.print("[red]Public: Yes[/red]")
            else:
                console.print("[green]Public: No[/green]")
            
            if result.get("issues", []):
                console.print("[yellow]Issues found:[/yellow]")
                for issue in result["issues"]:
                    console.print(f"  - {issue}")
            
            if result.get("public_containers", []):
                console.print("[yellow]Public containers:[/yellow]")
                for container in result["public_containers"]:
                    console.print(f"  - {container['name']} (Access: {container['access_level']})")
        
        elif provider == "GCP":
            bucket_name = result.get("bucket_name", "Unknown")
            console.print(f"[bold]{provider}: {bucket_name}[/bold]")
            
            if result.get("public", False):
                console.print("[red]Public: Yes[/red]")
            else:
                console.print("[green]Public: No[/green]")
            
            if result.get("issues", []):
                console.print("[yellow]Issues found:[/yellow]")
                for issue in result["issues"]:
                    console.print(f"  - {issue}")
            
            if result.get("public_access", []):
                console.print("[yellow]Public access rules:[/yellow]")
                for access in result["public_access"]:
                    console.print(f"  - Role: {access['role']}, Members: {', '.join(access['members'])}")
        
        console.print()
    
    def print_report(self):
        """Print a summary report of the scan results."""
        aws_results = self.results["aws"]
        azure_results = self.results["azure"]
        gcp_results = self.results["gcp"]
        
        console.print("\n[bold cyan]===== S3 Bucket Inspector Report =====[/bold cyan]")
        console.print(f"[cyan]Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/cyan]")
        console.print(f"[cyan]Target domains: {', '.join(self.domains)}[/cyan]")
        console.print(f"[cyan]Total buckets scanned: {len(self.potential_buckets)}[/cyan]\n")
        
        # Create summary table
        table = Table(title="Cloud Storage Summary")
        table.add_column("Provider")
        table.add_column("Found", justify="right")
        table.add_column("Public", justify="right", style="red")
        table.add_column("Private", justify="right", style="green")
        
        # AWS summary
        aws_public = sum(1 for r in aws_results if r.get("public", False))
        table.add_row(
            "AWS S3", 
            str(len(aws_results)), 
            str(aws_public), 
            str(len(aws_results) - aws_public)
        )
        
        # Azure summary
        azure_public = sum(1 for r in azure_results if r.get("public", False))
        table.add_row(
            "Azure Blob", 
            str(len(azure_results)), 
            str(azure_public), 
            str(len(azure_results) - azure_public)
        )
        
        # GCP summary
        gcp_public = sum(1 for r in gcp_results if r.get("public", False))
        table.add_row(
            "Google Cloud", 
            str(len(gcp_results)), 
            str(gcp_public), 
            str(len(gcp_results) - gcp_public)
        )
        
        # Total
        total_found = len(aws_results) + len(azure_results) + len(gcp_results)
        total_public = aws_public + azure_public + gcp_public
        table.add_row(
            "Total", 
            str(total_found), 
            str(total_public), 
            str(total_found - total_public),
            style="bold"
        )
        
        console.print(table)
        
        # Print public buckets
        if total_public > 0:
            console.print("\n[bold red]Public Storage Found:[/bold red]")
            
            # AWS public buckets
            for result in aws_results:
                if result.get("public", False):
                    bucket_name = result.get("bucket_name", "Unknown")
                    console.print(f"[red]AWS: {bucket_name}[/red]")
                    if result.get("public_files", []):
                        console.print(f"  - {len(result['public_files'])} public files found")
                    if result.get("issues", []):
                        for issue in result["issues"][:3]:  # Show first 3 issues
                            console.print(f"  - {issue}")
            
            # Azure public storage
            for result in azure_results:
                if result.get("public", False):
                    account_name = result.get("account_name", "Unknown")
                    console.print(f"[red]Azure: {account_name}[/red]")
                    if result.get("public_containers", []):
                        for container in result["public_containers"][:3]:  # Show first 3 containers
                            console.print(f"  - Container: {container['name']} (Access: {container['access_level']})")
            
            # GCP public buckets
            for result in gcp_results:
                if result.get("public", False):
                    bucket_name = result.get("bucket_name", "Unknown")
                    console.print(f"[red]GCP: {bucket_name}[/red]")
                    if result.get("public_access", []):
                        for access in result["public_access"][:3]:  # Show first 3 access rules
                            console.print(f"  - Role: {access['role']}")
        
        # Save results to file if specified
        if self.output_file:
            self.save_results()
            console.print(f"\n[green]Results saved to {self.output_file}[/green]")
    
    def export_to_csv(self, csv_file: str):
        """Export scan results to a CSV file."""
        import csv
        
        # Prepare the data
        rows = []
        
        # Header row
        header = ["Provider", "Name", "Public", "Issues"]
        rows.append(header)
        
        # AWS results
        for result in self.results["aws"]:
            bucket_name = result.get("bucket_name", "Unknown")
            is_public = "Yes" if result.get("public", False) else "No"
            issues = "; ".join(result.get("issues", []))
            rows.append(["AWS", bucket_name, is_public, issues])
        
        # Azure results
        for result in self.results["azure"]:
            account_name = result.get("account_name", "Unknown")
            is_public = "Yes" if result.get("public", False) else "No"
            issues = "; ".join(result.get("issues", []))
            rows.append(["Azure", account_name, is_public, issues])
        
        # GCP results
        for result in self.results["gcp"]:
            bucket_name = result.get("bucket_name", "Unknown")
            is_public = "Yes" if result.get("public", False) else "No"
            issues = "; ".join(result.get("issues", []))
            rows.append(["GCP", bucket_name, is_public, issues])
        
        # Write to CSV
        try:
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerows(rows)
        except Exception as e:
            console.print(f"[red]Error writing to CSV file: {str(e)}[/red]")
    
    def save_results(self):
        """Save results to a JSON file."""
        if not self.output_file:
            return
        
        output = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "target_domains": self.domains,
                "potential_buckets_checked": list(self.potential_buckets)
            },
            "results": self.results,
            "summary": {
                "aws": {
                    "total": len(self.results["aws"]),
                    "public": sum(1 for r in self.results["aws"] if r.get("public", False))
                },
                "azure": {
                    "total": len(self.results["azure"]),
                    "public": sum(1 for r in self.results["azure"] if r.get("public", False))
                },
                "gcp": {
                    "total": len(self.results["gcp"]),
                    "public": sum(1 for r in self.results["gcp"] if r.get("public", False))
                }
            }
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(output, f, indent=2)


def main():
    """Main entry point for the S3 Bucket Inspector tool."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="S3 Bucket Inspector - Find exposed cloud storage")
    parser.add_argument('-d', '--domains', required=False, 
                        help="Comma-separated list of target domains or bucket names")
    parser.add_argument('-f', '--file', help="File containing list of domains or bucket names (one per line)")
    parser.add_argument('-o', '--output', help="Output JSON file for results")
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help="Number of concurrent threads (default: 10)")
    parser.add_argument('-v', '--verbose', action='store_true', 
                        help="Enable verbose output")
    parser.add_argument('--csv', help="Save results to CSV file")
    parser.add_argument('--scan-account', choices=['aws', 'azure', 'gcp', 'all'],
                        help="Scan all buckets in the specified cloud account (requires valid credentials)")
    parser.add_argument('--disable-aws', action='store_true', help="Disable AWS S3 scanning")
    parser.add_argument('--disable-azure', action='store_true', help="Disable Azure Blob Storage scanning")
    parser.add_argument('--disable-gcp', action='store_true', help="Disable Google Cloud Storage scanning")
    parser.add_argument('--wordlist', help="Additional wordlist file for bucket name generation")
    args = parser.parse_args()
    
    # Get domains from arguments or environment variables
    domains = []
    
    if args.domains:
        domains.extend([d.strip() for d in args.domains.split(',') if d.strip()])
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                domains.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            console.print(f"[red]Error reading domains file: {str(e)}[/red]")
            return
    
    # Handle account scanning option
    scan_accounts = []
    if args.scan_account:
        if args.scan_account == 'all':
            scan_accounts = ['aws', 'azure', 'gcp']
        else:
            scan_accounts = [args.scan_account]
        
        # If we're doing account scanning and no domains are specified, use an empty list
        if not domains and scan_accounts:
            domains = []
    
    if not domains and not scan_accounts:
        # Try to get from environment
        env_domains = os.getenv('TARGET_DOMAINS')
        if env_domains:
            domains.extend([d.strip() for d in env_domains.split(',') if d.strip()])
    
    if not domains and not scan_accounts:
        console.print("[red]Error: No domains or bucket names specified, and no account scanning enabled.[/red]")
        console.print("[red]Use -d, -f, or --scan-account to specify what to scan.[/red]")
        return
    
    # Print enhanced banner
    console.print("""[bold blue]
    /* >>===========================================================================<< */
    /* ||                                                                           || */
    /* ||  ███████╗██████╗     ██████╗ ██╗   ██╗ ██████╗██╗  ██╗███████╗████████╗   || */
    /* ||  ██╔════╝╚════██╗    ██╔══██╗██║   ██║██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝   || */
    /* ||  ███████╗ █████╔╝    ██████╔╝██║   ██║██║     █████╔╝ █████╗     ██║      || */
    /* ||  ╚════██║ ╚═══██╗    ██╔══██╗██║   ██║██║     ██╔═██╗ ██╔══╝     ██║      || */
    /* ||  ███████║██████╔╝    ██████╔╝╚██████╔╝╚██████╗██║  ██╗███████╗   ██║      || */
    /* ||  ╚══════╝╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝      || */
    /* ||  ██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗ ██████╗ ██████╗   || */
    /* ||  ██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗  || */
    /* ||  ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ██║   ██║██████╔╝  || */
    /* ||  ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗  || */
    /* ||  ██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║  || */
    /* ||  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝  || */
    /* ||                                                                           || */
    /* >>===========================================================================<< */
    [/bold blue]
    [bold cyan]                            BUCKET INSPECTOR - by Jabour[/bold cyan]
                             [italic yellow]Find exposed cloud storage buckets[/italic yellow]
    """)
    
    # Show scan mode
    if scan_accounts:
        console.print(f"[bold green]ACCOUNT SCAN MODE: Will discover all buckets in {', '.join(scan_accounts)}[/bold green]")
    if domains:
        console.print(f"[bold cyan]Starting scan on {len(domains)} domain(s) or bucket(s): {', '.join(domains)}[/bold cyan]\n")
    
    # Load extra wordlist if specified
    extra_wordlist = []
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                extra_wordlist = [line.strip() for line in f if line.strip()]
            console.print(f"[green]Loaded {len(extra_wordlist)} additional bucket name patterns[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load wordlist file: {str(e)}[/yellow]")
    
    # Create and run the bucket inspector
    inspector = BucketInspector(
        domains=domains,
        output_file=args.output,
        verbose=args.verbose,
        threads=args.threads,
        disable_aws=args.disable_aws,
        disable_azure=args.disable_azure,
        disable_gcp=args.disable_gcp,
        extra_wordlist=extra_wordlist,
        scan_accounts=scan_accounts
    )
    
    try:
        # Start scanning
        inspector.scan_all_buckets()
        
        # Print report
        inspector.print_report()
        
        # Export to CSV if requested
        if args.csv:
            inspector.export_to_csv(args.csv)
            console.print(f"[green]Results exported to CSV: {args.csv}[/green]")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user. Generating report with partial results...[/yellow]")
        inspector.print_report()
    except Exception as e:
        console.print(f"[red]An error occurred during the scan: {str(e)}[/red]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())


if __name__ == "__main__":
    main() 