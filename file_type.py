# file_type.py

import magic
import os
import logging

logger = logging.getLogger("file_type_analyzer")

# class to determine a file's type using its magic number signature
class FileTypeAnalyzer:
    # initialize
    def __init__(self):
        try:
            self.magic_mime = magic.Magic(mime=True)
            self.magic_full = magic.Magic()
        except Exception as e:
            logger.error(f"Error initializing python-magic: {e}")
            self.magic_mime = self.magic_full = None

    # analyze a file to determine its size, signature type, and MIME type
    def analyze_file(self, file_path):
        result = {
            "size": 0,
            "signature_type": "Unknown",
            "mime_type": "Unknown",
        }
        if not os.path.exists(file_path):
            return result
            
        result["size"] = os.path.getsize(file_path)

        # use the python-magic library for initial identification
        if self.magic_mime and self.magic_full:
            try:
                result["mime_type"] = self.magic_mime.from_file(file_path)
                full_type = self.magic_full.from_file(file_path)

                # specifically indentify PE files for better classification
                if "PE32" in full_type:
                     result["signature_type"] = "PE Executable"
                else:
                     result["signature_type"] = full_type.split(',')[0]
            except Exception as e:
                 logger.warning(f"python-magic analysis failed: {e}")

        # manual signature check (as a fallback if magic fails)
        if result["signature_type"] == "Unknown":
            with open(file_path, 'rb') as f:
                header = f.read(4)

                # check for common file headers
                if header.startswith(b'MZ'):
                    result["signature_type"] = "PE Executable"
                elif header.startswith(b'%PDF'):
                    result["signature_type"] = "PDF Document"
        
        return result

