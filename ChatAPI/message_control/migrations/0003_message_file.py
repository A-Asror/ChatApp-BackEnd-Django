# Generated by Django 3.1 on 2021-08-24 12:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('message_control', '0002_auto_20210820_1751'),
    ]

    operations = [
        migrations.AddField(
            model_name='message',
            name='file',
            field=models.FileField(default='', upload_to='files'),
            preserve_default=False,
        ),
    ]