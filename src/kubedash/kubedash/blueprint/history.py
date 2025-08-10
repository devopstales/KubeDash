from flask import Blueprint, session, request, redirect, url_for

from kubedash.lib.helper_functions import get_logger
##############################################################
## Helpers
##############################################################

"""history Blueprint"""
history_bp = Blueprint("history", __name__)
logger = get_logger()

##############################################################
## history
##############################################################

@history_bp.before_app_request
def track_history():
    if 'history' not in session:
        session['history'] = []

    # Skip static or internal routes like /back
    if request.endpoint in ('static', 'history.back'):
        return

    entry = {
        'method': request.method,
        'path': request.path,
        'query_string': request.query_string.decode(),
        'form_data': request.form.to_dict() if request.method == 'POST' else None
    }

    history = session['history']

    if not history or history[-1] != entry:
        history.append(entry)

    session['history'] = history[-5:]


@history_bp.route('/back')
def back():
    history = session.get('history', [])
    
    if len(history) < 2:
        return redirect(url_for('index'))

    # Remove current page
    history.pop()
    target = history[-1]
    session['history'] = history

    if target['method'] == 'GET':
        query = '?' + target['query_string'] if target['query_string'] else ''
        return redirect(target['path'] + query)

    elif target['method'] == 'POST':
        session['last_form_data'] = target['form_data']
        return redirect(target['path'])

    return redirect(url_for('index'))