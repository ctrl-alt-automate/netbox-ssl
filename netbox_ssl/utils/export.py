"""
Certificate export utilities for various formats.

This module provides functionality to export certificate data in multiple
formats including CSV, JSON, YAML, and PEM.
"""

import csv
import io
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class ExportFormatChoices:
    """Available export format choices."""

    FORMAT_CSV = "csv"
    FORMAT_JSON = "json"
    FORMAT_YAML = "yaml"
    FORMAT_PEM = "pem"

    CHOICES = [
        (FORMAT_CSV, "CSV"),
        (FORMAT_JSON, "JSON"),
        (FORMAT_YAML, "YAML"),
        (FORMAT_PEM, "PEM"),
    ]

    @classmethod
    def get_choices(cls):
        """Get available choices, excluding YAML if not available."""
        if YAML_AVAILABLE:
            return cls.CHOICES
        return [c for c in cls.CHOICES if c[0] != cls.FORMAT_YAML]


class CertificateExporter:
    """
    Utility class for exporting certificate data in various formats.

    Supports CSV, JSON, YAML, and PEM export formats.
    """

    # Default fields to include in exports
    DEFAULT_FIELDS = [
        "id",
        "common_name",
        "serial_number",
        "fingerprint_sha256",
        "issuer",
        "valid_from",
        "valid_to",
        "days_remaining",
        "algorithm",
        "key_size",
        "status",
        "tenant",
        "sans",
    ]

    # Extended fields for detailed exports
    EXTENDED_FIELDS = DEFAULT_FIELDS + [
        "is_expired",
        "is_expiring_soon",
        "expiry_status",
        "private_key_location",
        "assignment_count",
        "created",
        "last_updated",
    ]

    @classmethod
    def certificate_to_dict(
        cls, certificate, fields: Optional[List[str]] = None, include_pem: bool = False
    ) -> Dict[str, Any]:
        """
        Convert a certificate to a dictionary.

        Args:
            certificate: Certificate model instance
            fields: List of fields to include (None = default fields)
            include_pem: Whether to include PEM content

        Returns:
            Dictionary representation of the certificate
        """
        fields = fields or cls.DEFAULT_FIELDS
        data = {}

        for field in fields:
            if field == "tenant":
                data[field] = certificate.tenant.name if certificate.tenant else None
            elif field == "sans":
                data[field] = certificate.sans or []
            elif field == "valid_from":
                data[field] = (
                    certificate.valid_from.isoformat() if certificate.valid_from else None
                )
            elif field == "valid_to":
                data[field] = (
                    certificate.valid_to.isoformat() if certificate.valid_to else None
                )
            elif field == "created":
                data[field] = (
                    certificate.created.isoformat() if certificate.created else None
                )
            elif field == "last_updated":
                data[field] = (
                    certificate.last_updated.isoformat()
                    if certificate.last_updated
                    else None
                )
            elif field == "assignment_count":
                data[field] = certificate.assignments.count()
            elif field == "days_remaining":
                data[field] = certificate.days_remaining
            elif field == "is_expired":
                data[field] = certificate.is_expired
            elif field == "is_expiring_soon":
                data[field] = certificate.is_expiring_soon
            elif field == "expiry_status":
                data[field] = certificate.expiry_status
            elif hasattr(certificate, field):
                data[field] = getattr(certificate, field)

        if include_pem and certificate.pem_content:
            data["pem_content"] = certificate.pem_content
            if certificate.issuer_chain:
                data["issuer_chain"] = certificate.issuer_chain

        return data

    @classmethod
    def export_to_csv(
        cls,
        certificates,
        fields: Optional[List[str]] = None,
        include_header: bool = True,
    ) -> str:
        """
        Export certificates to CSV format.

        Args:
            certificates: Queryset or list of Certificate instances
            fields: List of fields to include
            include_header: Whether to include header row

        Returns:
            CSV formatted string
        """
        fields = fields or cls.DEFAULT_FIELDS

        # Remove complex fields that don't work well in CSV
        csv_fields = [f for f in fields if f != "sans"]

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=csv_fields, extrasaction="ignore")

        if include_header:
            writer.writeheader()

        for cert in certificates:
            row = cls.certificate_to_dict(cert, fields=csv_fields)
            writer.writerow(row)

        return output.getvalue()

    @classmethod
    def export_to_json(
        cls,
        certificates,
        fields: Optional[List[str]] = None,
        include_pem: bool = False,
        pretty: bool = True,
    ) -> str:
        """
        Export certificates to JSON format.

        Args:
            certificates: Queryset or list of Certificate instances
            fields: List of fields to include
            include_pem: Whether to include PEM content
            pretty: Whether to format with indentation

        Returns:
            JSON formatted string
        """
        fields = fields or cls.DEFAULT_FIELDS
        data = []

        for cert in certificates:
            data.append(cls.certificate_to_dict(cert, fields=fields, include_pem=include_pem))

        if pretty:
            return json.dumps(data, indent=2, ensure_ascii=False)
        return json.dumps(data, ensure_ascii=False)

    @classmethod
    def export_to_yaml(
        cls,
        certificates,
        fields: Optional[List[str]] = None,
        include_pem: bool = False,
    ) -> str:
        """
        Export certificates to YAML format.

        Args:
            certificates: Queryset or list of Certificate instances
            fields: List of fields to include
            include_pem: Whether to include PEM content

        Returns:
            YAML formatted string

        Raises:
            ImportError: If PyYAML is not installed
        """
        if not YAML_AVAILABLE:
            raise ImportError(
                "PyYAML is required for YAML export. Install with: pip install pyyaml"
            )

        fields = fields or cls.DEFAULT_FIELDS
        data = []

        for cert in certificates:
            data.append(cls.certificate_to_dict(cert, fields=fields, include_pem=include_pem))

        return yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)

    @classmethod
    def export_to_pem(cls, certificates, include_chain: bool = True) -> str:
        """
        Export certificates to PEM format.

        Args:
            certificates: Queryset or list of Certificate instances
            include_chain: Whether to include certificate chain

        Returns:
            PEM formatted string with all certificates
        """
        pem_parts = []

        for cert in certificates:
            # Add comment header with certificate info
            pem_parts.append(f"# Certificate: {cert.common_name}")
            pem_parts.append(f"# Serial: {cert.serial_number}")
            pem_parts.append(f"# Expires: {cert.valid_to.strftime('%Y-%m-%d') if cert.valid_to else 'Unknown'}")
            pem_parts.append("")

            # Add the certificate PEM
            if cert.pem_content:
                pem_parts.append(cert.pem_content.strip())
            else:
                pem_parts.append("# No PEM content available")

            # Add the chain if requested and available
            if include_chain and cert.issuer_chain:
                pem_parts.append("")
                pem_parts.append("# Certificate Chain")
                pem_parts.append(cert.issuer_chain.strip())

            pem_parts.append("")
            pem_parts.append("")

        return "\n".join(pem_parts)

    @classmethod
    def export(
        cls,
        certificates,
        format: str,
        fields: Optional[List[str]] = None,
        include_pem: bool = False,
        **kwargs,
    ) -> str:
        """
        Export certificates to the specified format.

        Args:
            certificates: Queryset or list of Certificate instances
            format: Export format (csv, json, yaml, pem)
            fields: List of fields to include
            include_pem: Whether to include PEM content (json/yaml only)
            **kwargs: Additional format-specific arguments

        Returns:
            Formatted string in the requested format

        Raises:
            ValueError: If format is not supported
        """
        format = format.lower()

        if format == ExportFormatChoices.FORMAT_CSV:
            return cls.export_to_csv(
                certificates,
                fields=fields,
                include_header=kwargs.get("include_header", True),
            )
        elif format == ExportFormatChoices.FORMAT_JSON:
            return cls.export_to_json(
                certificates,
                fields=fields,
                include_pem=include_pem,
                pretty=kwargs.get("pretty", True),
            )
        elif format == ExportFormatChoices.FORMAT_YAML:
            return cls.export_to_yaml(
                certificates,
                fields=fields,
                include_pem=include_pem,
            )
        elif format == ExportFormatChoices.FORMAT_PEM:
            return cls.export_to_pem(
                certificates,
                include_chain=kwargs.get("include_chain", True),
            )
        else:
            raise ValueError(
                f"Unsupported export format: {format}. "
                f"Supported formats: {[c[0] for c in ExportFormatChoices.get_choices()]}"
            )

    @classmethod
    def get_content_type(cls, format: str) -> str:
        """
        Get the appropriate content type for a format.

        Args:
            format: Export format

        Returns:
            MIME content type string
        """
        content_types = {
            ExportFormatChoices.FORMAT_CSV: "text/csv",
            ExportFormatChoices.FORMAT_JSON: "application/json",
            ExportFormatChoices.FORMAT_YAML: "application/x-yaml",
            ExportFormatChoices.FORMAT_PEM: "application/x-pem-file",
        }
        return content_types.get(format.lower(), "text/plain")

    @classmethod
    def get_file_extension(cls, format: str) -> str:
        """
        Get the appropriate file extension for a format.

        Args:
            format: Export format

        Returns:
            File extension string (without dot)
        """
        extensions = {
            ExportFormatChoices.FORMAT_CSV: "csv",
            ExportFormatChoices.FORMAT_JSON: "json",
            ExportFormatChoices.FORMAT_YAML: "yaml",
            ExportFormatChoices.FORMAT_PEM: "pem",
        }
        return extensions.get(format.lower(), "txt")
