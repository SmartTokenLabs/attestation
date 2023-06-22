# Simple JS module to issue/verify/revoke EAS attestations with command-line request

## How to use:

1. install ncc globally: ```npm i -g @vercel/ncc```
2. run ```npm i```
3. build prod ```npm run build-prod```
4. install python to the system
5. test how it works with python example ```python3 test.py```

desired output:
```
--------- issue flow start ------------
--------- issue output: ------------
{"success":true,"data":"?type=eas&ticket=eNrFk02OGzAIhe-SdVQZMAaWk4nmElUX5u8AVSv1-HUyR8giIHmB7MfD9vfzMn7gulwBgPks18v494lLrG93kuRJqp81jb7gfhMmHHekVaDAdXlshrGiK7vFFLX2XiaGA7A38lA5yZaF2KOitX2DeTQ6C-4k_RahSawYe5xKjKkZq3lEMC-jECcElDAfoJTusCxIx2oB0Ja8XFGfzktVpn4cP8YElLaY7eNGhjybCLNL2-LZVBBWZ_lSYcZA9SnVuLIHJcaZAMJjaypn9DoKM6AVjopUET9FxovxEDm3fzxMEsF5Hc_Cn99_63V5fdFcvDodvPH0I86LP3K8K-g73tV-wpgDXf0wBO1Blnpw0ZLpE5fSal8OZrUFDwWC5wv64QOUN3Un5gGPYG0RMigLrpRe07QInfaOHOkZlTnThvuCKAqCmSRxACt_FY_x6z-DJAMV&secret=0x287c429e2131cfc3a9e19abb5e697222217bbc8b41d0c46af9e271ff96e795a8&mail=email2%40email3","balance":"0x2347b1a5abf0f6"}


--------- verify flow start ------------
--------- verify output: ------------
{'success': True, 'data': {'uid': '0xce246803299edc28bf69a6feb9cb094fa4f4f35d2fb3fff6ccad45fc24bafc9d', 'time': 1687436974, 'expirationTime': 0, 'payload': {'devconId': '222', 'ticketIdString': '333', 'ticketClass': 1, 'commitment': '0x0402b6e73ba00d21d85213a0cb530a3c5c6f5f42e32e14ec7bb3248134eb3765b51a4e1dee907a25f0a2d1ed322a8bbd4cc6af0928dd8edc1d20e338b467585ef5'}, 'revocable': True, 'signer': '0xCe88748Aedf95313d96559AB39254f332dfe8f9c', 'valid': True}, 'balance': '0x2347b1a5abf0f6'}

--------- revoke flow start ------------
--------- revoke output ------------
{'success': True, 'data': {'uid': '0x834a90333b02e4088b24962e62acb0d581113f65be7a53169b671664bff75fa7', 'time': 1687226742, 'expirationTime': 0, 'payload': {'devconId': '1', 'ticketIdString': '317454140484290350369362', 'ticketClass': 0, 'commitment': '0x04162d459a4f53c1698301aeaaed0fc294c981b0151ec8d91f56d7dc39cbe0f56e153d87e224cbe56305e42e5bb8680baac92a58af7699f3dc7ab58ee4572ac715'}, 'revocable': True, 'signer': '0x1eD53eD59CE09154f0b02281a07d18a579E86B8f', 'valid': False}, 'balance': '0x2289df97c8faef'}
```


## Commands:

Issue EAS attestation format: ```node dist/index.js <action> <network> <EAS_version> <conference_id> <issuer_privat_key> <user_email> <ticket_id> <ticket_class>```
Issue EAS attestation example: ```node dist/index.js issue sepolia 0.26 coolConference MHQCAQEEIGQfuD4sWJ3d8Tgr6fWq1xFR/I5LpbAzHatBOC5J1XT/oAcGBSuBBAAKoUQDQgAEyf+bzWwV7EgawmTO/Q7PEwvAMODoSg8ftD6baDvRRaC3zcVi4xZnOt6obzZw0bwT0XL/6AA6TfqhniIyPVQDuw== email@email.com 123 1```

Verify EAS attestation format: ```node dist/index.js <action> <network> <EAS_version> <conference_id> <issuer_privat_key> <ticket_data>```
Verify EAS attestation: ```node dist/index.js verify sepolia 0.26 coolConference MHQCAQEEIGQfuD4sWJ3d8Tgr6fWq1xFR/I5LpbAzHatBOC5J1XT/oAcGBSuBBAAKoUQDQgAEyf+bzWwV7EgawmTO/Q7PEwvAMODoSg8ftD6baDvRRaC3zcVi4xZnOt6obzZw0bwT0XL/6AA6TfqhniIyPVQDuw== eNrFU1uqG0AI3Uu+Q/Gt85vkdhOlH47jLKC00OV3kruEFK6MgiJHR875cYFvZJcrIqqecL3A3zuZj317sC8Vjri3DP6Oj5srEzyIrTFQ+/Js9iCRppaMOQu2Z/VAtQz3OSaJD9JapbBgcEkyr46YZN2otV8gNlWtl1cSLB1GRUI7a1Qmccwu69xlEh6hsrDSyzf3ikrrcbmSP3GwH8rHx/0DzhKyYQJRYIIvjFQfH2G3+BwaLDmAmU9PCzx3kjO6jbLmWSPOOXibzvZURhvTHM1k7u26018g8KY9Qc71LZzO1YWu8Cr8/vWn34ePN5cr+FLD9xEYv/QDcdiF7Cysx/E4HD/EY+LBT+7pK9rJnpH+73zB84yW6EjZynVIHAyYndkLdtGQGoETULEr1sCttnwVj5oNJzka5RXeRHIqagzaQq1zhgXMPBql1MjtNsbmVZ5To1vUj4wc9V15wM9/tS0DXw==```

Revoke EAS attestation format: ```node dist/index.js <action> <network> <EAS_version> <conference_id> <issuer_privat_key> <ticket_data>```
Revoke EAS attestation: ```node dist/index.js revoke sepolia 0.26 coolConference MHQCAQEEIGQfuD4sWJ3d8Tgr6fWq1xFR/I5LpbAzHatBOC5J1XT/oAcGBSuBBAAKoUQDQgAEyf+bzWwV7EgawmTO/Q7PEwvAMODoSg8ftD6baDvRRaC3zcVi4xZnOt6obzZw0bwT0XL/6AA6TfqhniIyPVQDuw== eNrFU1uqG0AI3Uu+Q/Gt85vkdhOlH47jLKC00OV3kruEFK6MgiJHR875cYFvZJcrIqqecL3A3zuZj317sC8Vjri3DP6Oj5srEzyIrTFQ+/Js9iCRppaMOQu2Z/VAtQz3OSaJD9JapbBgcEkyr46YZN2otV8gNlWtl1cSLB1GRUI7a1Qmccwu69xlEh6hsrDSyzf3ikrrcbmSP3GwH8rHx/0DzhKyYQJRYIIvjFQfH2G3+BwaLDmAmU9PCzx3kjO6jbLmWSPOOXibzvZURhvTHM1k7u26018g8KY9Qc71LZzO1YWu8Cr8/vWn34ePN5cr+FLD9xEYv/QDcdiF7Cysx/E4HD/EY+LBT+7pK9rJnpH+73zB84yW6EjZynVIHAyYndkLdtGQGoETULEr1sCttnwVj5oNJzka5RXeRHIqagzaQq1zhgXMPBql1MjtNsbmVZ5To1vUj4wc9V15wM9/tS0DXw==```

Module will output data in stringified JSON format, example:
```{'success': True, 'data': {'uid': '0xce246803299edc28bf69a6feb9cb094fa4f4f35d2fb3fff6ccad45fc24bafc9d', 'time': 1687436974, 'expirationTime': 0, 'payload': {'devconId': '222', 'ticketIdString': '333', 'ticketClass': 1, 'commitment': '0x0402b6e73ba00d21d85213a0cb530a3c5c6f5f42e32e14ec7bb3248134eb3765b51a4e1dee907a25f0a2d1ed322a8bbd4cc6af0928dd8edc1d20e338b467585ef5'}, 'revocable': True, 'signer': '0xCe88748Aedf95313d96559AB39254f332dfe8f9c', 'valid': True}, 'balance': '0x2347b1a5abf0f6'}```