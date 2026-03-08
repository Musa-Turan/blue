import yaml

# A dictionary to map common generic Sigma fields to Wazuh Elastic Common Schema (ECS) fields.
FIELD_MAP = {
    "EventID": "data.win.system.eventID",
    "Image": "data.win.eventdata.image",
    "CommandLine": "data.win.eventdata.commandLine",
    "ParentImage": "data.win.eventdata.parentImage",
    "ParentCommandLine": "data.win.eventdata.parentCommandLine",
    "TargetFilename": "data.win.eventdata.targetFilename",
    "DestinationIp": "data.srcip",
    "DestinationPort": "data.srcport",
    "User": "data.win.eventdata.user",
    "LogonType": "data.win.eventdata.logonType",
    "Hashes": "data.win.eventdata.hashes"
}

def translate_sigma_to_wazuh(sigma_yaml: str) -> dict:
    """
    Takes a raw Sigma rule (YAML string) and translates the core detection logic
    into a Wazuh Lucene/KQL query using PyYAML.
    Returns a dictionary with parsed metadata, the generated query, and any errors.
    """
    
    result = {
        "title": "Bilinmeyen Tehdit Avı Kuralı",
        "description": "Açıklama bulunamadı.",
        "logsource": "Bilinmiyor",
        "query": "",
        "error": None
    }
    
    try:
        rule = yaml.safe_load(sigma_yaml)
        if not isinstance(rule, dict):
            raise ValueError("Geçersiz YAML formatı. Kök eleman bir sözlük (dictionary) olmalı.")
            
        result["title"] = rule.get("title", result["title"])
        result["description"] = rule.get("description", result["description"])
        
        # Format logsource
        logsource = rule.get("logsource", {})
        if logsource:
            prod = logsource.get("product", "")
            cat = logsource.get("category", "")
            result["logsource"] = f"{prod} / {cat}".strip(" / ")
            
        # Parse detection
        detection = rule.get("detection", {})
        if not detection:
            result["error"] = "Kuralda 'detection' bloğu bulunamadı."
            return result
            
        selection = detection.get("selection", {})
        if not selection:
            # Sometimes the main block is named something else, but 'selection' is convention
            # We'll try to find the first dict inside detection that isn't 'condition'
            for k, v in detection.items():
                if k != 'condition' and isinstance(v, dict):
                    selection = v
                    break
                    
        if not selection:
             result["error"] = "Kural bloğunda geçerli bir arama kriteri (selection) bulunamadı."
             return result
             
        query_parts = []
        for key, value in selection.items():
            # Sigma allows modifiers like Image|endswith
            parts = key.split("|")
            field = parts[0]
            modifier = parts[1] if len(parts) > 1 else None
            
            # Map field to Wazuh ECS if possible
            wazuh_field = FIELD_MAP.get(field, f"data.{field.lower()}")
            
            # If value is a list, we need an OR condition inside parentheses
            values = value if isinstance(value, list) else [value]
            
            field_queries = []
            for val in values:
                val = str(val).strip()
                # Apply modifiers
                if modifier == "endswith":
                    lucene_val = f'*{val}'
                elif modifier == "startswith":
                    lucene_val = f'{val}*'
                elif modifier == "contains":
                    lucene_val = f'*{val}*'
                else:
                    lucene_val = val
                    
                # Escape backslashes for Lucene if it's a path
                if "\\" in lucene_val:
                    lucene_val = lucene_val.replace("\\", "\\\\")
                     
                field_queries.append(f'{wazuh_field}:"{lucene_val}"')
                
            if len(field_queries) > 1:
                query_parts.append(f'({" OR ".join(field_queries)})')
            elif len(field_queries) == 1:
                query_parts.append(field_queries[0])
            
        if query_parts:
            # Join with AND logic assuming all conditions in 'selection' must be met
            result["query"] = " AND ".join(query_parts)
        else:
            result["error"] = "Seçim kriteri (Condition) çevrilemedi. Lütfen kuralın formatını kontrol edin."

    except yaml.YAMLError as ye:
        result["error"] = f"YAML Sözdizimi Hatası: {str(ye)}"
    except Exception as e:
        result["error"] = f"Çeviri Hatası: {str(e)}"
        
    return result
