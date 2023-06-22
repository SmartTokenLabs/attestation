from os import path
from subprocess import Popen, PIPE
import json

# from pretix.base.models import OrderPosition

test_issue = True
test_verify = True
test_revoke = True

generator_path = 'dist/index.js'

ticket_to_verify = "eNrFUzmOGzAM_ItrI-ApkeV6jXxisYV46AFBAuT5kZ0nuPAQUCGQMyMK83WBHzQuV0RUPcf1An8_aUzftzvPUmGzzxbnn3i_TWWCO_FoNNS-PJpnDq4wbnRbc2XXTPUhKAXtCHPxxB64bC6kYUJTcLi6o0Y5PElGr5pgwzBcYK2YxZyKR1DxtEcpB8BMtJSdrKKkm0MVPKXkcqX5dN5mU-yja7sycvlQ9Y8bO6lsZqrdtj2fotkkw4DJvSvJYg9fY3d4BrjsJfvMaNEO3nuPzFWiO0li7fR6ksCLeJCc7Y9jm4dPucLz4vevP_06vb1oLl99Hb5x-oHz44-Cd4H_413ygiBAMXpyLIAiLFNCXpChDOtELMfWLdRMjdI5I5jEkKWD59BQXNJY3X6SfDIHiwq7mGhZREnmWBucrMpOirAImtlCxlTT3vpqPOD7H2ODAsQ."

ticket_to_revoke = "eNrFU1uqG0AI3Uu+Q/Gt85vkdhOlH47jLKC00OV3kruEFK6MgiJHR875cYFvZJcrIqqecL3A3zuZj317sC8Vjri3DP6Oj5srEzyIrTFQ+/Js9iCRppaMOQu2Z/VAtQz3OSaJD9JapbBgcEkyr46YZN2otV8gNlWtl1cSLB1GRUI7a1Qmccwu69xlEh6hsrDSyzf3ikrrcbmSP3GwH8rHx/0DzhKyYQJRYIIvjFQfH2G3+BwaLDmAmU9PCzx3kjO6jbLmWSPOOXibzvZURhvTHM1k7u26018g8KY9Qc71LZzO1YWu8Cr8/vWn34ePN5cr+FLD9xEYv/QDcdiF7Cysx/E4HD/EY+LBT+7pK9rJnpH+73zB84yW6EjZynVIHAyYndkLdtGQGoETULEr1sCttnwVj5oNJzka5RXeRHIqagzaQq1zhgXMPBql1MjtNsbmVZ5To1vUj4wc9V15wM9/tS0DXw=="
issuer_key_with_funds = "MHQCAQEEIGQfuD4sWJ3d8Tgr6fWq1xFR/I5LpbAzHatBOC5J1XT/oAcGBSuBBAAKoUQDQgAEyf+bzWwV7EgawmTO/Q7PEwvAMODoSg8ftD6baDvRRaC3zcVi4xZnOt6obzZw0bwT0XL/6AA6TfqhniIyPVQDuw=="

def test(
        # order_position: OrderPosition,
        path_to_key: str = './debug/key.pem',
        generator: str = generator_path,
        ticket_status: str = '1') -> str:
    print("--------- common flow starts ------------")
    if not path.isfile(path_to_key):
        raise ValueError(f'Key file not found in {path_to_key}')
    
    with open(path_to_key) as f:
        base64key = f.readlines()
    
    if ("----" in str(base64key[0])):
        base64key = base64key[1:-1]
    
    stripped_list = [s.strip() for s in base64key]

    # either generator is the full path to the java file or it sits next to the python file
    if path.isfile(generator):
        path_to_generator = path.abspath(generator)
    else:
        this_module_path = path.dirname(path.abspath(__file__))
        path_to_generator = path.join(this_module_path, generator)
    if not path.isfile(path_to_generator):
        raise ValueError(f'Generator file not found in {generator}')
    
    event_id = 222
    email = "email2@email3"
    ticket_id = 333
    if test_issue:
        print("\n--------- issue flow start ------------")
        process = Popen(['node', 
                        generator_path,
                        'issue',
                        'sepolia', 
                        '0.26',
                        # TODO add dropdown with conferenceId
                        str(event_id),
                        ''.join(stripped_list),
                        email, 
                        str(ticket_id), 
                        ticket_status],
                        stdout=PIPE, stderr=PIPE)

        process.wait()
        output = process.stdout.read().decode('utf-8')
        if output:
            print("--------- issue output: ------------")
            print(output)

        output = process.stderr.read().decode('utf-8')
        if output:
            print("--------- issue errors: ------------")
            print(output)

        error_message = process.stderr.read()
        if (error_message != b''):
            raise ValueError(f'Error message recieved: {error_message}')
    
    if test_verify:
        print("\n--------- verify flow start ------------")
        

        process = Popen(['node', 
                        generator_path,
                        'verify',
                        # TODO add dropdown with networks
                        'sepolia', 
                        #  'ethereum', 
                        '0.26',
                        # TODO add dropdown with conferenceId
                        str(event_id),
                        ''.join(stripped_list),
                        ticket_to_verify],
                        stdout=PIPE, stderr=PIPE)

        process.wait()
        validateOutput = process.stdout.read().decode('utf-8')
        print("--------- verify output: ------------")
        if validateOutput:
            try:
                validateOutputJson = json.loads(validateOutput)
                print(validateOutputJson)
            except:
                print("cant decode json .... input data: ", validateOutput)
            
        else:
            print("Decoded...")
            print(validateOutputJson)

        output = process.stderr.read().decode('utf-8')  
        if output:
            print("--------- verify errors: ------------")
            print(output)

    if test_revoke:
        print("\n--------- revoke flow start ------------")
        
        process = Popen(['node', 
                        generator_path,
                        'revoke',
                        # TODO add dropdown with networks
                        'sepolia', 
                        #  'ethereum', 
                        '0.26',
                        # TODO add dropdown with conferenceId
                        '1',
                        issuer_key_with_funds,
                        ticket_to_revoke],
                        stdout=PIPE, stderr=PIPE)

        process.wait()
        validateOutput = process.stdout.read().decode('utf-8')
        if validateOutput:
            print("--------- revoke output ------------")
            try:
                validateOutputJson = json.loads(validateOutput)
                print(validateOutputJson)
            except:
                print("cant decode json .... input data: ", validateOutput)
        
        output = process.stderr.read().decode('utf-8')
        if output:
            print("--------- revoke errors : ------------")
            print(output)

test()