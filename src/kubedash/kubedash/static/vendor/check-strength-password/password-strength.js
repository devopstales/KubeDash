function checkPasswordStrength(old_password, password) {
	var number     = /([0-9])/;
	var upperCase  = /([A-Z])/;
	var lowerCase  = /([a-z])/;
	var specialCharacters = /[ `!@#$%^ˇ&*()_+\-=\[\]{};':"\\|,.<>\/?~]/;


	var characters     = (password.length >= 6 && password.length <= 15 );
	var capitalletters = password.match(upperCase) ? 1 : 0;
	var loweletters    = password.match(lowerCase) ? 1 : 0;
	var numbers        = password.match(number) ? 1 : 0;
	var special        = specialCharacters.test(password) ? 1 : 0;
    var difference     = (old_password != password);

	this.update_info('length', password.length >= 6 && password.length <= 15);
    this.update_info('capital', capitalletters);
    this.update_info('small', loweletters);
    this.update_info('number', numbers);
    this.update_info('special', special);
    this.update_info('difference', difference);

	var total = characters + capitalletters + loweletters + numbers + special;
	this.password_meter(total);
}

function update_info(criterion, isValid) {
    var $passwordCriteria = $('#passwordCriterion').find('li[data-criterion="' + criterion + '"]');
    if (isValid) {
        $passwordCriteria.removeClass('invalid').addClass('valid');
    } else {
        $passwordCriteria.removeClass('valid').addClass('invalid');
    }
}

function password_meter(total) {
    var meter = $('#password-strength-status');
    meter.removeClass();
    if (total === 0) {
        meter.html('');
    } else if (total === 1) {
        meter.addClass('veryweak-password').html('very weak');
    } else if (total === 2) {
        meter.addClass('weak-password').html('weak');
    } else if (total === 3) {
        meter.addClass('medium-password').html('medium');
    } else if (total === 4) {
        meter.addClass('average-password').html('average');
    } else {
        meter.addClass('strong-password').html('strong');
    }
}

function checkPasswordConformation(new_password, confirm_new_password) {
    var same     = (new_password === confirm_new_password);

    this.update_info('same', same);
}