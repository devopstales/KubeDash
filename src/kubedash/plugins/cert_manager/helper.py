
#############################################################
## Helper Functions
##############################################################

def GenerateIssuerData(k8s_objects, k8s_object_list):
    for k8s_object in k8s_objects['items']:
        k8s_object_data = {
            "name": k8s_object['metadata']['name'],
            "status": k8s_object['status']['conditions'][-1]['status'],
            "reason": k8s_object['status']['conditions'][-1]['reason'],
        }
        if 'message' in k8s_object['status']['conditions'][-1]:
            k8s_object_data["message"] = k8s_object['status']['conditions'][-1]['message'].replace('"', '')
        if 'selfSigned' in k8s_object['spec']:
            k8s_object_data['type'] = "Sel Signed"
        if 'ca' in k8s_object['spec']:
            k8s_object_data['type'] = "CA"
            k8s_object_data['issuer_data'] = {
                "secret": k8s_object['spec']['ca']['secretName'],
            }
        if 'acme' in k8s_object['spec']:
            k8s_object_data['type'] = "ACME"
            k8s_object_data['issuer_data'] = {
                "email": None,
                "server": k8s_object['spec']['acme']['server'],
                "challenges": list(),
            }
            if 'email' in k8s_object['spec']['acme']:
                k8s_object_data['issuer_data']['email'] = k8s_object['spec']['acme']['email']
            for challenge in k8s_object['spec']['acme']['solvers']:
                if 'http01' in challenge:
                    k8s_object_data['issuer_data']['challenges'].append('http01')
                elif 'dns01' in challenge:
                    k8s_object_data['issuer_data']['challenges'].append('dns01')
        if 'vault' in k8s_object['spec']:
            k8s_object_data['type'] = "Vault"
            k8s_object_data['issuer_data'] = {
                "path": k8s_object['spec']['vault']['path'],
                "server": k8s_object['spec']['vault']['server'],
                "auth": None,
            }
            if 'appRole' in  k8s_object['spec']['vault']['auth']:
                k8s_object_data['issuer_data']['auth'] = 'App Role'
                k8s_object_data['issuer_data'] = {
                    "roleId": k8s_object['spec']['vault']['auth']['appRole']['roleId'],
                    "secret": k8s_object['spec']['vault']['auth']['appRole']['secretRef']['name'],
                }
            if 'tokenSecretRef' in  k8s_object['spec']['vault']['auth']:
                k8s_object_data['issuer_data']['auth'] = 'Token'
                k8s_object_data['issuer_data'] = {
                    "secret": k8s_object['spec']['vault']['auth']['tokenSecretRef']['name'],
                }
            if 'kubernetes' in  k8s_object['spec']['vault']['auth']:
                k8s_object_data['issuer_data']['auth'] = 'Kubernetes'
                k8s_object_data['issuer_data'] = {
                    "role": k8s_object['spec']['vault']['auth']['kubernetes']['role'],
                    'serviceA': k8s_object['spec']['vault']['auth']['kubernetes']['serviceAccountRef']['name'],
                }
        # Venafi
        k8s_object_list.append(k8s_object_data)
    return k8s_object_list
