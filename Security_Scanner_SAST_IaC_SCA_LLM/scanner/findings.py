
#Shape every rule (SAST, SCA, IaC) will return 
#Main class 
from dataclasses import dataclass

@dataclass
class Finding:
    rule_id: str
    severity: str
    attack_type_exposure: str
    file_path: str
    line: int
    message: str
    standard_ref: str

    