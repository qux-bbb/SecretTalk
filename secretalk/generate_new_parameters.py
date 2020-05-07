from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat

# Generate some parameters. These can be reused.
parameters = dh.generate_parameters(generator=2, key_size=2048,
                                    backend=default_backend())
parameters_bytes = parameters.parameter_bytes(Encoding.DER, ParameterFormat.PKCS3)
open('parameters_bytes', 'wb').write(parameters_bytes)