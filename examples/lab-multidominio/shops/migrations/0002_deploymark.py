from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("shops", "0001_initial")]

    operations = [
        migrations.CreateModel(
            name="DeployMark",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("version", models.CharField(max_length=20)),
            ],
        ),
    ]
