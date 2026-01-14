from flask import Blueprint, session, request, redirect, url_for

from lib.helper_functions import get_logger
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
    
    # Skip API endpoints - they shouldn't be tracked in navigation history
    if request.path.startswith('/api/'):
        return

    # Skip POST requests - they're usually form submissions that redirect
    # and would create duplicate entries in history
    if request.method == 'POST':
        return

    # If we're navigating back, skip adding this page to history
    # (it's already in history, we're just going back to it)
    if session.get('_navigating_back', False):
        session['_navigating_back'] = False
        return

    entry = {
        'method': request.method,
        'path': request.path,
        'query_string': request.query_string.decode(),
        'form_data': None
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

    # Remove current page from history
    current = history.pop()
    current_path = current['path']
    
    # Skip over entries that are the same path (with different query params or methods)
    # This handles cases where:
    # - The same page was added multiple times with different params
    # - POST requests that redirect to GET on the same path
    while history:
        target = history[-1]
        # If the target has the same path as current, skip it
        # (whether it's GET with different params, or POST that redirected)
        if target['path'] == current_path:
            skipped = history.pop()
            if not history:
                break
            # Update current_path to continue checking
            current_path = skipped['path']
        else:
            break
    
    # Get the previous page (the one we want to go back to)
    if not history:
        return redirect(url_for('index'))
    
    target = history[-1]
    
    # Set flag to skip adding the target page to history when we redirect
    # (it's already in history, we're just going back to it)
    session['_navigating_back'] = True
    session['history'] = history

    if target['method'] == 'GET':
        query = '?' + target['query_string'] if target['query_string'] else ''
        return redirect(target['path'] + query)

    # POST requests are no longer tracked, but handle legacy entries
    return redirect(url_for('index'))